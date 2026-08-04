#!/usr/bin/env python3
"""
ts_extract.py - tree-sitter based symbol/callsite extractor.

Replaces the regex extractors in build_code_model.py for non-Python languages with a real parse
tree. Regex can't resolve scope, can't see closures, and - the reason we switched - completely
misses DYNAMIC dispatch: call_user_func($x), obj[key](), $this->{$m}(), getattr(o,n)(), send(m).
Those are exactly the calls that hide the high-impact bugs (react2shell-style), so the tree
extractor emits them as callsites with syntax="dynamic-call" and sink_category="dynamic-call".

Outputs match build_code_model's existing shapes so the rest of the pipeline is unchanged:
  symbol:   {id,name,qualified_name,kind,language,file,start_line,end_line,confidence,class_name,params}
  callsite: {file,line,caller_name,callee,receiver,raw,syntax,sink_category}
  (build_code_model fills id/caller_symbol via its own make_symbol/containing_symbol.)

Falls back gracefully: if tree-sitter or a language parser isn't available, ts_available()
returns False and build_code_model keeps its regex path. Parser objects are cached.

Pinned stack that ships parsers INSIDE the wheel (no network at runtime):
  tree-sitter==0.21.3, tree-sitter-languages==1.10.2
"""
from __future__ import annotations
import warnings
warnings.filterwarnings("ignore")

_PARSERS={}
_OK=None

# our language id -> tree-sitter-languages grammar name
LANG2TS={
    "javascript":"javascript","typescript":"typescript","tsx":"tsx","jsx":"javascript",
    "php":"php","ruby":"ruby","go":"go","java":"java","c_sharp":"c_sharp","csharp":"c_sharp",
    "rust":"rust","c":"c","cpp":"cpp","kotlin":"kotlin","scala":"scala","python":"python",
}

def ts_available():
    global _OK
    if _OK is None:
        try:
            import tree_sitter_languages as tsl
            # Don't trust import alone - the common failure is a tree-sitter CORE version mismatch
            # (0.25.x core vs the 0.21-era API tree-sitter-languages 1.10.2 was built against),
            # which imports fine but throws on get_parser. So actually build a parser.
            tsl.get_parser("php")
            _OK=True
        except Exception as e:
            import sys
            print(f"[ts_extract] tree-sitter unavailable, using regex fallback: {e}", file=sys.stderr)
            print("[ts_extract] fix: pip install 'tree-sitter==0.21.3' "
                  "'tree-sitter-languages==1.10.2' --break-system-packages", file=sys.stderr)
            _OK=False
    return _OK

def _parser(lang):
    ts=LANG2TS.get(lang)
    if not ts: return None
    if ts not in _PARSERS:
        try:
            import tree_sitter_languages as tsl
            _PARSERS[ts]=tsl.get_parser(ts)
        except Exception:
            _PARSERS[ts]=None
    return _PARSERS[ts]

def supports(lang): return ts_available() and LANG2TS.get(lang) in _grammars_ok(lang)
def _grammars_ok(lang):
    return {LANG2TS.get(lang)} if _parser(lang) else set()

# ---- per-language node-type maps (measured against the 1.10.2 grammars) ----
# function/method definition nodes, and the field holding the name
FUNC_DEFS={
    "php":{"function_definition":"name","method_declaration":"name"},
    "javascript":{"function_declaration":"name","method_definition":"name",
        "arrow_function":None,"function":None,"generator_function_declaration":"name"},
    "typescript":{"function_declaration":"name","method_definition":"name","arrow_function":None,
        "function":None,"method_signature":"name","abstract_method_signature":"name"},
    "tsx":{"function_declaration":"name","method_definition":"name","arrow_function":None,"function":None},
    "ruby":{"method":"name","singleton_method":"name"},
    "go":{"function_declaration":"name","method_declaration":"name"},
    "java":{"method_declaration":"name","constructor_declaration":"name"},
    "c_sharp":{"method_declaration":"name","constructor_declaration":"name","local_function_statement":"name"},
    "rust":{"function_item":"name"},
    "c":{"function_definition":None},
    "cpp":{"function_definition":None},
    "kotlin":{"function_declaration":"simple_identifier"},
    "scala":{"function_definition":"name"},
}
CLASS_DEFS={
    "php":{"class_declaration","interface_declaration","trait_declaration"},
    "javascript":{"class_declaration"},"typescript":{"class_declaration"},"tsx":{"class_declaration"},
    "ruby":{"class","module"},"go":{"type_declaration"},"java":{"class_declaration","interface_declaration"},
    "c_sharp":{"class_declaration","interface_declaration","struct_declaration"},
    "rust":{"impl_item","struct_item","trait_item"},"kotlin":{"class_declaration"},"scala":{"class_definition","object_definition","trait_definition"},
}
# static call nodes + the receiver/name structure differ; we read text generically
CALL_NODES={
    "php":{"function_call_expression","member_call_expression","scoped_call_expression",
        "nullsafe_member_call_expression"},
    "javascript":{"call_expression","new_expression"},
    "typescript":{"call_expression","new_expression"},"tsx":{"call_expression","new_expression"},
    "ruby":{"call","command","command_call","method_call"},
    "go":{"call_expression"},
    "java":{"method_invocation","object_creation_expression"},
    "c_sharp":{"invocation_expression","object_creation_expression"},
    "rust":{"call_expression","macro_invocation"},
    "c":{"call_expression"},"cpp":{"call_expression"},
    "kotlin":{"call_expression"},"scala":{"call_expression"},
}
# dynamic-dispatch markers (language-specific): these are the calls regex misses
DYN_CALL_FUNCS={
    "php":{"call_user_func","call_user_func_array","func_get_args"},
    "javascript":{"apply","call","bind"}, "typescript":{"apply","call","bind"},
    "ruby":{"send","public_send","__send__","method","define_method","instance_eval","class_eval"},
    "python":{"getattr","setattr","__getattribute__","__import__"},
}
# sink callee names (kept minimal/high-signal; build_code_model.classify_sink also runs)
def text_of(node, src): return src[node.start_byte:node.end_byte].decode("utf8","replace")

def _name_from_call(node, lang, src):
    """Return (callee, receiver, syntax). Detect dynamic dispatch."""
    # the "function" being called is usually the first non-arg child or a 'function'/'name' field
    fn=node.child_by_field_name("function") or node.child_by_field_name("name")
    if fn is None:
        # ruby 'call' uses 'method' field; php scoped uses children
        fn=node.child_by_field_name("method")
    # PHP/JS member call whose method-name slot is an expression (obj->{$x}(), obj[$x]()):
    # the call node has no resolvable name field -> dynamic dispatch.
    if fn is None and node.type in ("member_call_expression","nullsafe_member_call_expression",
            "scoped_call_expression"):
        recv=node.child_by_field_name("object") or node.child_by_field_name("scope")
        receiver=text_of(recv, src) if recv is not None else ""
        return ("(dynamic)", receiver, "dynamic-call")
    target=fn if fn is not None else (node.children[0] if node.children else None)
    if target is None: return ("","","bare-call")
    ttype=target.type
    ttext=text_of(target, src)
    # dynamic: subscript/variable/computed member as the callee
    dynamic=False; receiver=""; callee=""
    if ttype in ("subscript_expression","element_access_expression","index_expression"):
        dynamic=True; callee="(dynamic)"
    elif ttype in ("variable_name","identifier","simple_identifier") and ttext.startswith("$"):
        # php variable function $fn()
        dynamic=True; callee="(dynamic)"
    elif ttype in ("member_access_expression","member_expression","field_expression",
                   "selector_expression","scoped_property_access_expression",
                   "navigation_expression","field_access"):
        # receiver.method  -> split last segment
        parts=ttext.replace("->",".").replace("::",".").split(".")
        callee=parts[-1].strip() if parts else ttext
        receiver=".".join(parts[:-1]).strip()
        # computed member: obj[x]() or obj->{$m}()  shows up as braces/brackets in text
        if "{" in callee or "[" in callee or callee.startswith("$"): dynamic=True; callee="(dynamic)"
    else:
        callee=ttext.split("(")[0].split(".")[-1].split("::")[-1].strip()
    # explicit dynamic-dispatch functions
    base=callee.lstrip("\\").split("\\")[-1]
    if base in DYN_CALL_FUNCS.get(lang,set()):
        dynamic=True
    syntax="dynamic-call" if dynamic else ("member-call" if receiver else "bare-call")
    if dynamic and callee in ("","(dynamic)"):
        callee=base if base else "(dynamic)"
    return (callee, receiver, syntax)

def _node_name(node, lang, src):
    f=node.child_by_field_name("name")
    if f is not None: return text_of(f, src)
    # fallback: first identifier child
    for c in node.children:
        if c.type in ("name","identifier","simple_identifier","field_identifier"):
            return text_of(c, src)
    return ""

def extract(rel, lang, text, module, make_symbol, classify_sink, KEYWORDS):
    """Return (symbols, callsites) in build_code_model's shapes, or None to signal fallback."""
    p=_parser(lang)
    if p is None: return None
    src=text.encode("utf8","replace")
    try:
        tree=p.parse(src)
    except Exception:
        return None
    fdefs=FUNC_DEFS.get(lang,{}); cdefs=CLASS_DEFS.get(lang,set()); calls=CALL_NODES.get(lang,set())
    if not fdefs and not calls: return None
    symbols=[]; callsites=[]
    def line_of(node): return node.start_point[0]+1
    def endline(node): return node.end_point[0]+1

    # walk once, track class stack for qualified names + caller attribution
    func_spans=[]  # (start,end,qualified) for caller attribution
    def qual(cls,name): return f"{module}.{cls}.{name}" if cls else f"{module}.{name}"

    def visit(node, class_stack):
        nt=node.type
        new_stack=class_stack
        if nt in cdefs:
            cname=_node_name(node, lang, src)
            if cname:
                symbols.append(make_symbol(rel,lang,cname,f"{module}.{cname}","class",
                    line_of(node),endline(node),confidence="high"))
                new_stack=class_stack+[cname]
        elif nt in fdefs:
            name=_node_name(node, lang, src)
            if name and name not in KEYWORDS:
                cls=class_stack[-1] if class_stack else ""
                kind="method" if cls else "function"
                q=qual(cls,name)
                params=[]
                pl=node.child_by_field_name("parameters")
                if pl is not None:
                    for c in pl.children:
                        if c.type in ("parameter","required_parameter","optional_parameter",
                            "simple_parameter","formal_parameter","typed_parameter","identifier"):
                            t=text_of(c,src).strip()
                            if t and t not in("(",")",","): params.append(t[:40])
                symbols.append(make_symbol(rel,lang,name,q,kind,line_of(node),endline(node),
                    class_name=cls,params=params,confidence="high"))
                func_spans.append((node.start_byte,node.end_byte,q))
        if nt in calls:
            callee,receiver,syntax=_name_from_call(node, lang, src)
            if callee and callee not in KEYWORDS:
                raw=text_of(node,src)[:240].replace("\n"," ")
                cat=None
                try: cat=classify_sink(callee,receiver)
                except Exception: cat=None
                if syntax=="dynamic-call" and not cat: cat="dynamic-call"
                callsites.append({"file":rel,"line":line_of(node),"caller_name":"",
                    "callee":callee,"receiver":receiver or "","raw":raw,"syntax":syntax,
                    "sink_category":cat or "","_start":node.start_byte})
        for c in node.children:
            visit(c, new_stack)

    visit(tree.root_node, [])
    # attribute each callsite to the innermost enclosing function span
    func_spans.sort(key=lambda s:(s[0],-(s[1])))
    for cs in callsites:
        sb=cs.pop("_start",None)
        owner=""
        if sb is not None:
            best=None
            for st,en,q in func_spans:
                if st<=sb<=en and (best is None or (en-st)<(best[1]-best[0])):
                    best=(st,en,q)
            owner=best[2] if best else ""
        cs["caller_name"]=owner
    return symbols, callsites