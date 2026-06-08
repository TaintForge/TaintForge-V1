#!/usr/bin/env python3
"""
build_code_model.py - deterministic structural extractor for the source-model stage.

Function/method-level graph. Zero required runtime deps: stdlib ast (python) + regex
extractors run everywhere. tree-sitter can be layered in later without changing output shape.

Output:
  workspace/CODE_MODEL.json
  workspace/symbols.json
  workspace/callsites.json
  workspace/dataflow.json
  workspace/proof_ledger.json
"""
from __future__ import annotations
import argparse, ast, collections, datetime as _dt, hashlib, json, os, re, sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

EXT_LANG = {".py":"python",".js":"javascript",".mjs":"javascript",".cjs":"javascript",
    ".jsx":"javascript",".ts":"typescript",".tsx":"tsx",".java":"java",".go":"go",".rb":"ruby",
    ".php":"php",".cs":"c_sharp",".c":"c",".h":"c",".cpp":"cpp",".cc":"cpp",".hpp":"cpp",
    ".rs":"rust",".kt":"kotlin",".scala":"scala",".swift":"swift"}

SKIP_DIRS = {".git","node_modules","vendor","dist","build","__pycache__",".venv","venv",
    "target",".next","coverage",".tox",".pytest_cache",".mypy_cache",".turbo",
    "tmp","log","logs","public/assets","storage",".bundle"}

MAX_BFS_DEPTH = int(os.environ.get("TF_PATH_DEPTH","8"))
MAX_PATHS_PER_ENTRY = int(os.environ.get("TF_MAX_PATHS_PER_ENTRY","200"))
MAX_PATHS_PER_SINK = int(os.environ.get("TF_MAX_PATHS_PER_SINK","80"))
MAX_FILE_BYTES = int(os.environ.get("TF_MAX_FILE_BYTES", str(2_000_000)))

SINK_CATEGORIES: Dict[str, set] = {
    "sql": {"query","exec","execute","execute_query","raw","rawquery","rawQuery",
        "mysqli_query","mysql_query","pg_query","prepare","sequelize.query","knex.raw",
        "whereRaw","orderByRaw","find_by_sql"},
    "command": {"system","shell_exec","passthru","proc_open","popen","pcntl_exec","execSync",
        "spawn","spawnSync","execFile","execFileSync","child_process.exec","subprocess.call",
        "subprocess.run","subprocess.Popen","os.system"},
    "code-eval": {"eval","assert","create_function","Function","vm.runInNewContext",
        "vm.runInThisContext","compile","exec","load","class_eval","instance_eval"},
    "deserialization": {"unserialize","deserialize","pickle.loads","yaml.load","Marshal.load",
        "JSON.parse","ObjectInputStream","readObject","BinaryFormatter.Deserialize"},
    "file-path": {"include","include_once","require","require_once","file_get_contents","fopen",
        "open","readfile","file_put_contents","fwrite","send_file","sendFile","download",
        "readFile","readFileSync","move_uploaded_file","ZipFile","tarfile.open"},
    "ssrf-net": {"curl_exec","fsockopen","get_headers","requests.get","requests.post",
        "urllib.request.urlopen","fetch","axios.get","axios.post","http.get","https.get",
        "Net::HTTP.get","open-uri.open_uri"},
    "xss-output": {"send","html","render","write","echo","print","innerHTML",
        "dangerouslySetInnerHTML","res.send","response.write"},
    "redirect": {"redirect","redirect_to","sendRedirect","Redirect","res.redirect"},
    "resource-load": {"find","findById","find_by_id","findOne","load","lookup","where","first",
        "find_by","get_object_or_404","findUnique"},
}
SINK_BY_NAME: Dict[str,str] = {}
_GENERIC_DOTTED_TAILS = {"get","post","put","patch","delete","send","write","open","load",
    "find","where","first","render","redirect"}
for _cat,_names in SINK_CATEGORIES.items():
    for _n in _names:
        SINK_BY_NAME[_n.lower()] = _cat
        _tail = _n.split(".")[-1].lower()
        if "." not in _n or _tail not in _GENERIC_DOTTED_TAILS:
            SINK_BY_NAME[_tail] = _cat

# Sink-scope guard: resource-load and xss-output match extremely common ORM/render calls
# (find/where/first/render/send/...). On a large app they explode the sink set and the proof
# ledger into tens of thousands of units. Keep them OPT-IN (TF_NOISY_SINKS=1). Default OFF =
# only high-signal sinks (sql/command/code-eval/deserialization/file-path/ssrf-net/redirect).
if os.environ.get("TF_NOISY_SINKS","0") != "1":
    for _name in list(SINK_BY_NAME):
        if SINK_BY_NAME[_name] in ("resource-load","xss-output"):
            del SINK_BY_NAME[_name]

SOURCE_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("http-request", re.compile(r"\b(req|request|params|headers|cookies|session)\b", re.I)),
    ("http-body", re.compile(r"\b(req\.(body|query|params|headers|cookies)|request\.(POST|GET|args|form|json|headers|cookies|data))\b", re.I)),
    ("route-param", re.compile(r"\b(params\[|param\(|route_params|@PathVariable|@RequestParam|c\.Param\()", re.I)),
    ("env-or-cli", re.compile(r"\b(argv|process\.env|os\.environ|ENV\[|getenv\()\b", re.I)),
    ("upload", re.compile(r"\b(files|uploaded_file|multipart|multer|FileUpload|request\.files)\b", re.I)),
]
GUARD_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("authn", re.compile(r"\b(authenticate|authenticated|require_login|login_required|current_user|isAuthenticated|logged_in|@login_required|authorize_request)\b", re.I)),
    ("authz", re.compile(r"\b(authorize|authorization|can\?|policy|permission|permit\?|allowed\?|require_role|hasRole|isAdmin|admin_required|Pundit|CanCan)\b", re.I)),
    ("ownership", re.compile(r"\b(owner|user_id|account_id|tenant_id|organization_id|workspace_id|belongs_to|owned_by)\b", re.I)),
    ("csrf", re.compile(r"\b(csrf|csrf_token|protect_from_forgery|verify_authenticity_token|SameSite)\b", re.I)),
    ("sanitizer", re.compile(r"\b(escape|sanitize|htmlspecialchars|encodeURIComponent|parameterize|prepared|bind_param|allowlist|whitelist|validator|validate|filter_var|permit\()\b", re.I)),
]
KEYWORDS = {"if","for","while","switch","catch","function","return","array","list","isset",
    "empty","unset","new","clone","and","or","not","foreach","elseif","else","do","try",
    "throw","match","fn","use","class","interface","trait","global","static","public",
    "private","protected","const","var","let","int","string","bool","boolean","float",
    "double","void","async","await","yield","require","include","import","export","typeof",
    "sizeof","case","default","super","this","self","true","false","null","nil","None","lambda"}
ROUTE_METHODS = {"get","post","put","patch","delete","head","options","all","use"}
STATE_CHANGING = {"POST","PUT","PATCH","DELETE"}

def sha1_short(value: str, n: int = 12) -> str:
    return hashlib.sha1(value.encode("utf-8","replace")).hexdigest()[:n]
def detect_language(path: str) -> Optional[str]:
    return EXT_LANG.get(os.path.splitext(path)[1].lower())
def rel_module(rel: str) -> str:
    return os.path.splitext(rel)[0].replace(os.sep,"/").replace("/",".")
def iter_source_files(root: str) -> Iterable[str]:
    for dirpath,dirnames,filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            full = os.path.join(dirpath,fn)
            if detect_language(full):
                try:
                    if os.path.getsize(full) <= MAX_FILE_BYTES: yield full
                except OSError: continue
def line_no(text: str, offset: int) -> int:
    return text.count("\n",0,max(0,offset)) + 1
def find_matching_brace(text: str, open_pos: int) -> int:
    depth=0; quote=None; esc=False; i=open_pos
    while i < len(text):
        ch=text[i]
        if quote:
            if esc: esc=False
            elif ch=="\\": esc=True
            elif ch==quote: quote=None
        else:
            if ch in ('"',"'","`"): quote=ch
            elif ch=="{": depth+=1
            elif ch=="}":
                depth-=1
                if depth<=0: return i
        i+=1
    return len(text)
def strip_comments_for_line(line: str) -> str:
    for marker in ("//","#"):
        idx=line.find(marker)
        if idx>=0: return line[:idx]
    return line
def make_symbol(rel,lang,name,qualified_name,kind,start_line,end_line,**extra):
    sid=f"{rel}::{qualified_name or name}@{start_line}"
    out={"id":sid,"name":name,"qualified_name":qualified_name or name,"kind":kind,
        "language":lang,"file":rel,"start_line":int(start_line),
        "end_line":int(max(start_line,end_line)),"confidence":extra.pop("confidence","high")}
    out.update({k:v for k,v in extra.items() if v not in (None,"",[])})
    return out
def add_module_symbol(rel,lang,line_count):
    return make_symbol(rel,lang,"<module>",f"{rel_module(rel)}.<module>","module",1,max(1,line_count),confidence="high")
def parse_params(src: str) -> List[str]:
    src=src.strip()
    if not src: return []
    params=[]
    for p in src.split(","):
        p=p.strip()
        if not p: continue
        p=re.sub(r"=.*$","",p).strip(); p=re.sub(r"^[*&]+","",p)
        parts=re.split(r"\s+",p); params.append(parts[-1].strip("$:*&"))
    return [p for p in params if p]
def safe_unparse(node):
    try: return ast.unparse(node)
    except Exception: return node.__class__.__name__

def extract_python_symbols(rel,lang,text):
    symbols=[]; imports=[]; module=rel_module(rel)
    try: tree=ast.parse(text)
    except SyntaxError: return extract_generic_symbols(rel,lang,text), imports
    class Visitor(ast.NodeVisitor):
        def __init__(self): self.scope=[]; self.class_stack=[]
        def visit_Import(self,node):
            for alias in node.names:
                imports.append({"kind":"import","alias":alias.asname or alias.name.split(".")[-1],
                    "target":alias.name,"file":rel,"line":node.lineno})
        def visit_ImportFrom(self,node):
            mod="."*node.level+(node.module or "")
            for alias in node.names:
                imports.append({"kind":"from-import","alias":alias.asname or alias.name,
                    "target":f"{mod}.{alias.name}".strip("."),"module":mod,"name":alias.name,
                    "file":rel,"line":node.lineno})
        def visit_ClassDef(self,node):
            q=".".join([module]+self.scope+[node.name])
            symbols.append(make_symbol(rel,lang,node.name,q,"class",node.lineno,
                getattr(node,"end_lineno",node.lineno),
                bases=[safe_unparse(b) for b in node.bases],
                decorators=[safe_unparse(d) for d in node.decorator_list]))
            self.scope.append(node.name); self.class_stack.append(node.name)
            self.generic_visit(node); self.class_stack.pop(); self.scope.pop()
        def visit_FunctionDef(self,node):
            self._function(node,"method" if self.class_stack else "function")
        def visit_AsyncFunctionDef(self,node):
            self._function(node,"method" if self.class_stack else "function",async_=True)
        def _function(self,node,kind,async_=False):
            name=getattr(node,"name","<anon>"); q=".".join([module]+self.scope+[name])
            args=getattr(node,"args",None); params=[]
            if args is not None:
                params=[a.arg for a in getattr(args,"posonlyargs",[])+getattr(args,"args",[])+getattr(args,"kwonlyargs",[])]
            decorators=[safe_unparse(d) for d in getattr(node,"decorator_list",[])]
            symbols.append(make_symbol(rel,lang,name,q,kind,getattr(node,"lineno",1),
                getattr(node,"end_lineno",getattr(node,"lineno",1)),
                class_name=self.class_stack[-1] if self.class_stack else "",
                params=params,decorators=decorators,async_=async_))
            self.scope.append(name); self.generic_visit(node); self.scope.pop()
    Visitor().visit(tree)
    return symbols, imports

def extract_generic_symbols(rel,lang,text):
    symbols=[]; module=rel_module(rel); line_count=max(1,text.count("\n")+1)
    class_spans=[]
    class_re=re.compile(r"\b(?:export\s+)?(?:abstract\s+|final\s+|public\s+|private\s+|protected\s+)?(?:class|interface|trait|module)\s+([A-Za-z_$][\w$]*)[^\{\n]*(\{)?",re.M)
    for m in class_re.finditer(text):
        name=m.group(1); start=line_no(text,m.start())
        if m.group(2):
            open_pos=text.find("{",m.start(),m.end()+200)
            close=find_matching_brace(text,open_pos) if open_pos>=0 else m.end()
            end=line_no(text,close)
            class_spans.append((name,start,end,open_pos+1 if open_pos>=0 else m.end(),close))
        else:
            end=line_count; class_spans.append((name,start,end,m.end(),len(text)))
        symbols.append(make_symbol(rel,lang,name,f"{module}.{name}","class",start,end,confidence="medium"))
    def containing_class(start_idx):
        best=None
        for c in class_spans:
            if c[3]<=start_idx<=c[4]:
                if best is None or (c[4]-c[3])<(best[4]-best[3]): best=c
        return (best[0],best) if best else ("",None)
    patterns=[]
    if lang in {"javascript","typescript","tsx"}:
        patterns.extend([
            (re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{",re.M),"function",1,2),
            (re.compile(r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*)?\(([^)]*)\)\s*=>\s*\{",re.M),"function",1,2),
            (re.compile(r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)\s*\{",re.M),"function",1,2)])
    elif lang=="php":
        patterns.append((re.compile(r"\b(?:public|private|protected|static|final|abstract|\s)*function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{",re.M),"function",1,2))
    elif lang=="go":
        patterns.append((re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{",re.M),"function",1,2))
    elif lang=="rust":
        patterns.append((re.compile(r"\b(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\(([^)]*)\)[^{;]*\{",re.M),"function",1,2))
    elif lang in {"java","c_sharp","kotlin","scala","swift","c","cpp"}:
        patterns.append((re.compile(r"\b(?:public|private|protected|internal|static|final|async|virtual|override|inline|extern|pub|func|fun|def|[A-Za-z_][\w:<>,\[\]\s*&]+)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:throws\s+[\w,\s]+)?\{",re.M),"function",1,2))
    else:
        patterns.append((re.compile(r"\b(?:def|function|func|fn)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)",re.M),"function",1,2))
    seen={(s["file"],s["qualified_name"],s["start_line"]) for s in symbols}
    for pat,default_kind,name_group,params_group in patterns:
        for m in pat.finditer(text):
            name=m.group(name_group)
            if name in KEYWORDS: continue
            start_line=line_no(text,m.start())
            open_pos=text.find("{",m.end()-1,min(len(text),m.end()+500))
            end_line=line_no(text,find_matching_brace(text,open_pos)) if open_pos>=0 else line_count
            cls,_span=containing_class(m.start())
            kind="method" if cls else default_kind
            q=f"{module}.{cls}.{name}" if cls else f"{module}.{name}"
            key=(rel,q,start_line)
            if key in seen: continue
            seen.add(key)
            symbols.append(make_symbol(rel,lang,name,q,kind,start_line,end_line,
                class_name=cls,params=parse_params(m.group(params_group)),confidence="medium"))
    if lang=="ruby":
        symbols.extend(extract_ruby_symbols(rel,lang,text,existing={s["id"] for s in symbols}))
    if lang in {"javascript","typescript","tsx","java","c_sharp","kotlin","scala","swift"}:
        for cls,_st,_end,body_start,body_end in class_spans:
            body=text[body_start:body_end]
            meth_re=re.compile(r"(?m)^\s*(?:public|private|protected|static|async|get|set|override|final|abstract|\s)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")
            for mm in meth_re.finditer(body):
                name=mm.group(1)
                if name in KEYWORDS or name==cls: continue
                abs_start=body_start+mm.start(); start_line=line_no(text,abs_start)
                open_pos=text.find("{",body_start+mm.end()-1,min(body_end,body_start+mm.end()+200))
                end_line=line_no(text,find_matching_brace(text,open_pos)) if open_pos>=0 else start_line
                q=f"{module}.{cls}.{name}"; key=(rel,q,start_line)
                if key in seen: continue
                seen.add(key)
                symbols.append(make_symbol(rel,lang,name,q,"method",start_line,end_line,
                    class_name=cls,params=parse_params(mm.group(2)),confidence="medium"))
    return sorted(symbols,key=lambda s:(s["start_line"],s.get("end_line",0),s["qualified_name"]))

def extract_ruby_symbols(rel,lang,text,existing):
    symbols=[]; module=rel_module(rel); stack=[]; lines=text.splitlines()
    for idx,line in enumerate(lines,start=1):
        stripped=line.strip()
        m_cls=re.match(r"(?:class|module)\s+([A-Za-z_:][\w:]*)",stripped)
        if m_cls:
            name=m_cls.group(1).split("::")[-1]
            stack.append({"type":"class","name":name,"start":idx,"children":[]}); continue
        m_def=re.match(r"def\s+(?:(self)\.)?([A-Za-z_]\w*[!?=]?)",stripped)
        if m_def:
            cls=next((x["name"] for x in reversed(stack) if x["type"]=="class"),"")
            name=m_def.group(2)
            q=f"{module}.{cls}.{name}" if cls else f"{module}.{name}"
            sym=make_symbol(rel,lang,name,q,"method" if cls else "function",idx,len(lines),class_name=cls,confidence="medium")
            stack.append({"type":"def","name":name,"start":idx,"symbol":sym}); continue
        if stripped=="end" or stripped.startswith("end "):
            if stack:
                obj=stack.pop()
                if obj.get("type")=="def":
                    sym=obj["symbol"]; sym["end_line"]=idx
                    if sym["id"] not in existing: symbols.append(sym); existing.add(sym["id"])
                elif obj.get("type")=="class":
                    q=f"{module}.{obj['name']}"
                    sym=make_symbol(rel,lang,obj["name"],q,"class",obj["start"],idx,confidence="medium")
                    if sym["id"] not in existing: symbols.append(sym); existing.add(sym["id"])
    return symbols

def extract_symbols_and_imports(rel,lang,text):
    if lang=="python": symbols,imports=extract_python_symbols(rel,lang,text)
    else: symbols,imports=extract_generic_symbols(rel,lang,text),[]
    imports.extend(extract_imports(rel,lang,text))
    return symbols,imports

def extract_imports(rel,lang,text):
    imports=[]
    if lang in {"javascript","typescript","tsx"}:
        for m in re.finditer(r"import\s+([^;]+?)\s+from\s+['\"]([^'\"]+)['\"]",text):
            spec,mod=m.group(1),m.group(2); line=line_no(text,m.start())
            default_part=spec.split(",",1)[0].strip()
            if default_part and not default_part.startswith("{") and default_part!="*":
                imports.append({"kind":"import-default","alias":default_part,"target":mod,"module":mod,"file":rel,"line":line})
            brace=re.search(r"\{([^}]+)\}",spec)
            if brace:
                for part in brace.group(1).split(","):
                    part=part.strip()
                    if not part: continue
                    bits=re.split(r"\s+as\s+",part); name=bits[0].strip(); alias=bits[-1].strip()
                    imports.append({"kind":"import-named","alias":alias,"name":name,"target":f"{mod}.{name}","module":mod,"file":rel,"line":line})
            ns=re.match(r"\*\s+as\s+([A-Za-z_$][\w$]*)",spec.strip())
            if ns:
                imports.append({"kind":"import-namespace","alias":ns.group(1),"target":mod,"module":mod,"file":rel,"line":line})
        for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['\"]([^'\"]+)['\"]\)",text):
            imports.append({"kind":"require","alias":m.group(1),"target":m.group(2),"module":m.group(2),"file":rel,"line":line_no(text,m.start())})
        for m in re.finditer(r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(['\"]([^'\"]+)['\"]\)",text):
            mod=m.group(2)
            for part in m.group(1).split(","):
                name=part.strip().split(":")[-1].strip()
                if name: imports.append({"kind":"require-named","alias":name,"name":name,"target":f"{mod}.{name}","module":mod,"file":rel,"line":line_no(text,m.start())})
    elif lang=="php":
        for m in re.finditer(r"^\s*use\s+([^;]+);",text,re.M):
            target=m.group(1).strip(); alias=target.split("\\")[-1]
            am=re.search(r"\s+as\s+([A-Za-z_]\w*)",target,re.I)
            if am: alias=am.group(1); target=re.split(r"\s+as\s+",target,flags=re.I)[0]
            imports.append({"kind":"use","alias":alias,"target":target,"file":rel,"line":line_no(text,m.start())})
    elif lang=="ruby":
        for m in re.finditer(r"\b(require|require_relative)\s+['\"]([^'\"]+)['\"]",text):
            imports.append({"kind":m.group(1),"alias":os.path.basename(m.group(2)),"target":m.group(2),"module":m.group(2),"file":rel,"line":line_no(text,m.start())})
    return imports

def symbol_contains_line(symbol,line):
    return symbol.get("kind") in {"function","method","module"} and symbol["start_line"]<=line<=symbol["end_line"]
def containing_symbol(symbols,line):
    candidates=[s for s in symbols if symbol_contains_line(s,line)]
    if not candidates: return symbols[0]
    candidates.sort(key=lambda s:((s["end_line"]-s["start_line"]),0 if s["kind"]!="module" else 10))
    return candidates[0]
def normalize_callee(name):
    name=name.strip().strip("$@"); name=name.split("(")[0]
    name=re.split(r"->|::|\.",name)[-1]; return name
def classify_sink(callee,receiver=""):
    c=callee.lower(); r=receiver.strip("$"); dotted=f"{r}.{callee}" if r else callee
    return SINK_BY_NAME.get(dotted.lower(),"") or SINK_BY_NAME.get(c,"")

def extract_callsites(file_info):
    rel=file_info["rel"]; symbols=file_info["symbols"]; text=file_info["text"]
    lines=text.splitlines(); out=[]; seen=set()
    member_re=re.compile(r"(?P<receiver>\$?[A-Za-z_$][\w$]*)(?:\s*(?:\.|->|::)\s*)(?P<name>[A-Za-z_$][\w$]*)\s*\(")
    bare_re=re.compile(r"(?<![\w$.:>])(?P<name>[A-Za-z_$][\w$]*)\s*\(")
    construct_re=re.compile(r"\b(?P<name>include|include_once|require|require_once|eval|assert|echo|print)\b\s*[\(\'\"$@A-Za-z_]",re.I)
    def add(line_no_,name,receiver,raw,syntax):
        short=normalize_callee(name)
        if not short or short in KEYWORDS: return
        line_text=lines[line_no_-1] if 0<=line_no_-1<len(lines) else ""
        before=line_text[:max(0,line_text.find(name))]
        if re.search(r"\b(function|def|func|fn|class)\s+$",before): return
        key=(line_no_,short,receiver or "")
        if key in seen: return
        seen.add(key)
        caller=containing_symbol(symbols,line_no_); cat=classify_sink(short,receiver)
        out.append({"id":f"{rel}:{line_no_}:{sha1_short((receiver or '')+':'+short+':'+raw,8)}",
            "file":rel,"line":line_no_,"caller_symbol":caller["id"],"caller_name":caller["qualified_name"],
            "callee":short,"receiver":receiver or "","raw":raw.strip()[:240],"syntax":syntax,"sink_category":cat or ""})
    for i,raw_line in enumerate(lines,start=1):
        line=strip_comments_for_line(raw_line)
        if not line.strip(): continue
        for m in member_re.finditer(line): add(i,m.group("name"),m.group("receiver"),m.group(0),"member-call")
        for m in bare_re.finditer(line):
            prefix=line[max(0,m.start()-3):m.start()]
            if "." in prefix or "->" in prefix or "::" in prefix: continue
            add(i,m.group("name"),"",m.group(0),"bare-call")
        for m in construct_re.finditer(line): add(i,m.group("name"),"",m.group(0),"language-construct")
    return out

def extract_sources_guards(file_info):
    rel=file_info["rel"]; symbols=file_info["symbols"]
    sources=[]; guards=[]; seen_src=set(); seen_guard=set()
    for i,line in enumerate(file_info["text"].splitlines(),start=1):
        caller=containing_symbol(symbols,i)
        for kind,pat in SOURCE_PATTERNS:
            if pat.search(line):
                key=(i,kind)
                if key not in seen_src:
                    seen_src.add(key)
                    sources.append({"id":f"source:{rel}:{i}:{kind}","file":rel,"line":i,
                        "caller_symbol":caller["id"],"kind":kind,"expr":line.strip()[:240],"confidence":"medium"})
        for kind,pat in GUARD_PATTERNS:
            if pat.search(line):
                key=(i,kind)
                if key not in seen_guard:
                    seen_guard.add(key)
                    guards.append({"id":f"guard:{rel}:{i}:{kind}","file":rel,"line":i,
                        "caller_symbol":caller["id"],"kind":kind,"expr":line.strip()[:240],"confidence":"medium"})
    return sources,guards

def resolve_module_path(current_rel,module_spec,files):
    if not module_spec: return None
    base_dir=os.path.dirname(current_rel); candidates=[]
    if module_spec.startswith("."):
        p=os.path.normpath(os.path.join(base_dir,module_spec)).replace("\\","/")
        candidates.append(p)
        candidates.extend([p+ext for ext in EXT_LANG])
        candidates.extend([p+"/index"+ext for ext in EXT_LANG])
        candidates.extend([p+"/__init__.py"])
    else:
        modpath=module_spec.replace(".","/").strip("/")
        candidates.extend([modpath+ext for ext in EXT_LANG])
        candidates.extend([modpath+"/index"+ext for ext in EXT_LANG])
        candidates.extend([modpath+"/__init__.py"])
        candidates.extend([os.path.join(base_dir,os.path.basename(modpath))+ext for ext in EXT_LANG])
    for c in candidates:
        c=os.path.normpath(c).replace("\\","/")
        if c in files: return c
    return None

class Resolver:
    def __init__(self,symbols,imports,files):
        self.symbols=symbols; self.files=set(files); self.by_id={s["id"]:s for s in symbols}
        self.by_file_name=collections.defaultdict(list); self.by_simple=collections.defaultdict(list)
        self.by_tail=collections.defaultdict(list); self.class_methods=collections.defaultdict(list)
        self.file_exports=collections.defaultdict(list); self.imports_by_file=collections.defaultdict(list)
        for imp in imports: self.imports_by_file[imp.get("file","")].append(imp)
        for s in symbols:
            if s["kind"] not in {"function","method","class"}: continue
            name=s["name"]; self.by_file_name[(s["file"],name)].append(s); self.by_simple[name].append(s)
            parts=s["qualified_name"].split(".")
            for n in range(1,min(4,len(parts))+1): self.by_tail[".".join(parts[-n:])].append(s)
            cls=s.get("class_name") or ""
            if cls and s["kind"]=="method": self.class_methods[(cls,name)].append(s)
            self.file_exports[s["file"]].append(s)
    def resolve(self,call):
        callee=call["callee"]; receiver=call.get("receiver","").strip("$"); file=call["file"]
        sink_cat=call.get("sink_category") or classify_sink(callee,receiver)
        same=self.by_file_name.get((file,callee),[])
        if same: return same[0]["id"],same[0],"same-file","high"
        if receiver:
            m=self.class_methods.get((receiver,callee),[])
            if len(m)==1: return m[0]["id"],m[0],"class-method","high"
            if len(m)>1: return m[0]["id"],m[0],"class-method-ambiguous","medium"
            for imp in self.imports_by_file.get(file,[]):
                if imp.get("alias")==receiver:
                    mf=resolve_module_path(file,imp.get("module") or imp.get("target",""),self.files)
                    if mf:
                        cands=[s for s in self.file_exports.get(mf,[]) if s["name"]==callee]
                        if cands: return cands[0]["id"],cands[0],"imported-module-member","high"
            cands=[s for s in self.by_simple.get(callee,[]) if s["kind"]=="method"]
            if len(cands)==1: return cands[0]["id"],cands[0],"unique-method-name","medium"
            if len(cands)>1: return f"external:{receiver}.{callee}",None,"unresolved-instance-method","low"
        for imp in self.imports_by_file.get(file,[]):
            if imp.get("alias")==callee:
                mf=resolve_module_path(file,imp.get("module") or imp.get("target",""),self.files)
                target_name=imp.get("name") or callee
                if mf:
                    cands=[s for s in self.file_exports.get(mf,[]) if s["name"]==target_name]
                    if cands: return cands[0]["id"],cands[0],"imported-name","high"
        all_cands=self.by_simple.get(callee,[])
        if len(all_cands)==1: return all_cands[0]["id"],all_cands[0],"unique-name","medium"
        if len(all_cands)>1:
            same_dir=[s for s in all_cands if os.path.dirname(s["file"])==os.path.dirname(file)]
            if len(same_dir)==1: return same_dir[0]["id"],same_dir[0],"same-directory-name","medium"
            return f"external:{callee}",None,"ambiguous-name","low"
        if sink_cat: return f"builtin:sink:{callee}",None,"builtin-sink","high"
        return f"external:{receiver+'.' if receiver else ''}{callee}",None,"external-or-dynamic","low"

def build_call_graph(callsites,resolver,symbols_by_id):
    edges=[]; seen=set()
    for c in callsites:
        to_id,target,resolution,confidence=resolver.resolve(c)
        caller=symbols_by_id.get(c["caller_symbol"],{})
        sink_category=c.get("sink_category") or classify_sink(c["callee"],c.get("receiver",""))
        key=(c["caller_symbol"],to_id,c["file"],c["line"],c["callee"])
        if key in seen: continue
        seen.add(key)
        edge={"from":c["caller_symbol"],"to":to_id,"callee":c["callee"],"receiver":c.get("receiver",""),
            "caller_symbol":c["caller_symbol"],"caller_name":caller.get("qualified_name",""),
            "caller_file":caller.get("file",c["file"]),"caller_line":caller.get("start_line",c["line"]),
            "callsite_id":c["id"],"callsite_file":c["file"],"callsite_line":c["line"],"raw":c.get("raw",""),
            "resolution":resolution,"confidence":confidence,
            "kind":"sink-call" if sink_category else "user-call" if target else "external-call",
            "sink_category":sink_category}
        if target:
            edge.update({"callee_symbol":target["id"],"callee_name":target["qualified_name"],
                "callee_file":target["file"],"callee_line":target["start_line"]})
        edges.append(edge)
    return sorted(edges,key=lambda e:(e.get("callsite_file",""),e.get("callsite_line",0),e.get("callee","")))

def infer_handler_expr(rest):
    rest=rest.strip()
    if rest.startswith(","): rest=rest[1:]
    rest=rest.split("//",1)[0]
    if re.search(r"=>\s*\{|function\s*\(",rest): return "<inline-handler>"
    parts=[p.strip() for p in rest.split(",") if p.strip()]
    if not parts: return ""
    cand=parts[-1]; cand=re.sub(r"[\)\];].*$","",cand).strip(); cand=cand.strip("[]")
    if "." in cand or re.match(r"[A-Za-z_$][\w$]*$",cand): return cand
    return cand[:120]

def infer_php_handler_expr(rest):
    rest=rest.strip()
    if re.search(r"function\s*\(",rest): return "<inline-handler>"
    m=re.search(r"([A-Za-z_][\w\\]*)::class\s*,\s*['\"]([A-Za-z_]\w*)['\"]",rest)
    if m:
        cls=m.group(1).split("\\")[-1]; return f"{cls}.{m.group(2)}"
    m=re.search(r"['\"]([A-Za-z_][\w\\]*)@([A-Za-z_]\w*)['\"]",rest)
    if m:
        cls=m.group(1).split("\\")[-1]; return f"{cls}.{m.group(2)}"
    return infer_handler_expr(rest)

def resolve_handler_expr(expr,rel,resolver):
    if not expr or expr=="<inline-handler>" or resolver is None: return expr,"","inline-or-unresolved"
    expr=expr.strip().strip("&"); receiver=""; callee=expr
    if "." in expr: receiver,callee=expr.rsplit(".",1)
    elif "::" in expr: receiver,callee=expr.rsplit("::",1)
    fake_call={"file":rel,"callee":normalize_callee(callee),"receiver":receiver.split(".")[-1],"sink_category":""}
    to_id,target,resolution,_c=resolver.resolve(fake_call)
    if target: return target["qualified_name"],to_id,resolution
    return expr,"",resolution

def rails_target_to_handler(target):
    if "#" not in target: return target
    ctrl,action=target.split("#",1)
    cls="".join(part.capitalize() for part in ctrl.split("/")[-1].split("_"))+"Controller"
    return f"{cls}.{action}"

def extract_entry_points(file_info,resolver=None):
    rel=file_info["rel"]; lang=file_info["lang"]; text=file_info["text"]; symbols=file_info["symbols"]
    eps=[]
    # Client-side JS/TS (frontend assets, specs, vendored UI) matches router.get('/x') patterns
    # for CLIENT routers (Vue/React/jQuery), which are NOT server attack surface. Excluding these
    # stops thousands of bogus "entry points" (e.g. app/assets/javascripts/...) from drowning the
    # real server routes in the coverage priority. Server-side JS (Express/Koa) lives elsewhere.
    CLIENT_JS_DIR=re.compile(r"(^|/)(assets|javascripts?|frontend|webpack|client|public|static|"
                             r"spec|specs|test|tests|__tests__|stories|storybook|node_modules)(/|$)", re.I)
    is_client_js = (lang in {"javascript","typescript","tsx"} and CLIENT_JS_DIR.search(rel))
    def handler_from_line(line,default=""):
        sym=containing_symbol(symbols,line)
        if sym and sym.get("kind") in {"function","method"} and sym.get("file")==rel:
            return sym["qualified_name"],sym["id"],"containing-symbol"
        return default,"","heuristic"
    decorator_re=re.compile(r"@(?P<obj>[\w.]+)\.(?P<method>route|get|post|put|patch|delete|head|options)\(\s*['\"](?P<path>[^'\"]+)['\"]",re.I)
    spring_re=re.compile(r"@(?P<method>Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]?(?P<path>[^'\")]+)?",re.I)
    for pat in (decorator_re,spring_re):
        for m in pat.finditer(text):
            line=line_no(text,m.start())
            after=[s for s in symbols if s["kind"] in {"function","method"} and s["start_line"]>=line]
            after.sort(key=lambda s:s["start_line"])
            handler=after[0] if after else None
            method=m.group("method").upper().replace("MAPPING","")
            if method in ("ROUTE","REQUEST"): method="ANY"
            eps.append({"kind":"http-route","method":method,"path":m.group("path") or "",
                "handler":handler["qualified_name"] if handler else "",
                "handler_symbol":handler["id"] if handler else "",
                "handler_resolution":"decorator-next-symbol" if handler else "unresolved",
                "file":rel,"line":line,"confidence":"high" if handler else "medium",
                "raw":text.splitlines()[line-1].strip()[:240] if text.splitlines() else ""})
    if lang in {"javascript","typescript","tsx","go"} and not is_client_js:
        js_route_re=re.compile(r"\b(?P<router>[A-Za-z_$][\w$]*)\.(?P<method>get|post|put|patch|delete|head|options|all|use|HandleFunc|Handle)\(\s*['\"](?P<path>[^'\"]+)['\"](?P<rest>[^\n;]*)",re.I)
        for m in js_route_re.finditer(text):
            line=line_no(text,m.start()); method=m.group("method")
            method="ANY" if method.lower() in {"use","all","handle","handlefunc"} else method.upper()
            rest=m.group("rest") or ""; handler_expr=infer_handler_expr(rest)
            hn,hs,hr=resolve_handler_expr(handler_expr,rel,resolver) if resolver else (handler_expr,"","heuristic")
            if not hn: hn,hs,hr=handler_from_line(line,handler_expr)
            eps.append({"kind":"http-route","method":method,"path":m.group("path"),
                "handler":hn or handler_expr,"handler_symbol":hs,"handler_resolution":hr,
                "file":rel,"line":line,"confidence":"high" if hs else "medium",
                "raw":text.splitlines()[line-1].strip()[:240] if text.splitlines() else ""})
    if lang=="php":
        php_route_re=re.compile(r"\bRoute::(?P<method>get|post|put|patch|delete|any|match)\(\s*['\"](?P<path>[^'\"]+)['\"](?P<rest>[^;]*)",re.I)
        for m in php_route_re.finditer(text):
            line=line_no(text,m.start())
            method="ANY" if m.group("method").lower() in {"any","match"} else m.group("method").upper()
            handler_expr=infer_php_handler_expr(m.group("rest") or "")
            hn,hs,hr=resolve_handler_expr(handler_expr,rel,resolver) if resolver else (handler_expr,"","heuristic")
            eps.append({"kind":"http-route","method":method,"path":m.group("path"),
                "handler":hn or handler_expr,"handler_symbol":hs,"handler_resolution":hr,
                "file":rel,"line":line,"confidence":"high" if hs else "medium",
                "raw":text.splitlines()[line-1].strip()[:240] if text.splitlines() else ""})
    rails_route_re=re.compile(r"\b(?P<method>get|post|put|patch|delete|match)\s+['\"](?P<path>[^'\"]+)['\"](?:[^\n#]*?to:\s*['\"](?P<to>[^'\"]+)['\"])?",re.I)
    for m in rails_route_re.finditer(text):
        line=line_no(text,m.start()); target=m.group("to") or ""
        hn=rails_target_to_handler(target) if target else ""
        eps.append({"kind":"http-route","method":m.group("method").upper(),"path":m.group("path"),
            "handler":hn,"handler_symbol":"","handler_resolution":"rails-route-target" if hn else "unresolved",
            "file":rel,"line":line,"confidence":"medium",
            "raw":text.splitlines()[line-1].strip()[:240] if text.splitlines() else ""})
    if lang=="ruby" and re.search(r"controllers?|routes?",rel,re.I):
        for s in symbols:
            if s["kind"] in {"function","method"} and s["name"] in {"index","show","create","update","destroy","new","edit"}:
                eps.append({"kind":"controller-action","method":"","path":"","handler":s["qualified_name"],
                    "handler_symbol":s["id"],"handler_resolution":"controller-action-name",
                    "file":rel,"line":s["start_line"],"confidence":"medium","raw":""})
    uniq={}
    for e in eps:
        key=(e["file"],e["line"],e.get("method",""),e.get("path",""))
        old=uniq.get(key)
        if old is None or (not old.get("handler_symbol") and e.get("handler_symbol")): uniq[key]=e
    return sorted(uniq.values(),key=lambda e:(e["file"],e["line"],e.get("method",""),e.get("path","")))

def build_graph_indexes(edges):
    adj=collections.defaultdict(list); rev=collections.defaultdict(list)
    for e in edges: adj[e["from"]].append(e); rev[e["to"]].append(e)
    return adj,rev

def find_forward_paths(start,adj,max_depth,max_paths):
    paths=[]; q=collections.deque([(start,[],{start})])
    while q and len(paths)<max_paths:
        node,path,seen=q.popleft()
        if len(path)>=max_depth: continue
        for e in adj.get(node,[]):
            nxt=e["to"]; new_path=path+[e]
            if e.get("sink_category") or nxt.startswith("builtin:sink:"):
                paths.append(new_path)
                if len(paths)>=max_paths: break
            if nxt.startswith("external:") or nxt.startswith("builtin:") or nxt in seen: continue
            q.append((nxt,new_path,seen|{nxt}))
    return paths

def find_backward_paths(start,rev,entry_symbols,max_depth,max_paths):
    paths=[]; q=collections.deque([(start,[],{start})])
    while q and len(paths)<max_paths:
        node,path,seen=q.popleft()
        if len(path)>=max_depth: continue
        callers=rev.get(node,[])
        if not callers:
            if path: paths.append(list(reversed(path)))
            continue
        for e in callers:
            prev=e["from"]; new_path=path+[e]
            if prev in entry_symbols:
                paths.append(list(reversed(new_path)))
                if len(paths)>=max_paths: break
            elif prev not in seen:
                q.append((prev,new_path,seen|{prev}))
    return paths

def edge_path_to_summary(path):
    if not path: return {"symbols":[],"callsites":[]}
    symbols=[path[0]["from"]]; callsites=[]
    for e in path:
        symbols.append(e["to"])
        callsites.append({"file":e.get("callsite_file",""),"line":e.get("callsite_line",0),
            "callee":e.get("callee",""),"sink_category":e.get("sink_category",""),"resolution":e.get("resolution","")})
    return {"symbols":symbols,"callsites":callsites}

def path_confidence(path):
    if not path: return "low"
    vals=[e.get("confidence","low") for e in path]
    if all(v=="high" for v in vals): return "high"
    if any(v=="low" for v in vals): return "low"
    return "medium"

def sink_edge_to_obj(e):
    return {"id":f"sink:{e.get('callsite_file','')}:{e.get('callsite_line',0)}:{e.get('callee','')}",
        "category":e.get("sink_category",""),"callee":e.get("callee",""),"receiver":e.get("receiver",""),
        "file":e.get("callsite_file",""),"line":e.get("callsite_line",0),"caller_symbol":e.get("from",""),
        "raw":e.get("raw",""),"resolution":e.get("resolution",""),"confidence":e.get("confidence","")}

def build_dataflow(symbols,edges,entry_points,sources,guards):
    adj,rev=build_graph_indexes(edges)
    entry_symbols={e.get("handler_symbol") for e in entry_points if e.get("handler_symbol")}
    sink_edges=[e for e in edges if e.get("sink_category") or e["to"].startswith("builtin:sink:")]
    attack_paths=[]
    for ep in entry_points:
        h=ep.get("handler_symbol")
        if not h: continue
        for p in find_forward_paths(h,adj,MAX_BFS_DEPTH,MAX_PATHS_PER_ENTRY):
            sink=p[-1]
            attack_paths.append({"entry":{"method":ep.get("method",""),"path":ep.get("path",""),
                "file":ep.get("file",""),"line":ep.get("line",0),"handler_symbol":h},
                "sink":{"callee":sink.get("callee",""),"category":sink.get("sink_category",""),
                "file":sink.get("callsite_file",""),"line":sink.get("callsite_line",0)},
                "path":edge_path_to_summary(p),"confidence":path_confidence(p)})
    sink_backtraces=[]
    for e in sink_edges[:2000]:
        for p in find_backward_paths(e["to"],rev,entry_symbols,MAX_BFS_DEPTH,MAX_PATHS_PER_SINK):
            if not p: continue
            sink_backtraces.append({"sink":{"callee":e.get("callee",""),"category":e.get("sink_category",""),
                "file":e.get("callsite_file",""),"line":e.get("callsite_line",0)},
                "path":edge_path_to_summary(p),"confidence":path_confidence(p)})
    open_edges=[]
    for e in edges:
        if e.get("resolution") not in {"external-or-dynamic","ambiguous-name","unresolved-instance-method"}: continue
        recv=(e.get("receiver") or "").lower(); callee_l=(e.get("callee") or "").lower()
        if callee_l in ROUTE_METHODS and recv in {"app","router","route","routes","r","mux"}: continue
        if callee_l=="get" and recv in {"req","request","params","args","headers","cookies","session"}: continue
        open_edges.append({"from":e.get("from"),"caller_name":e.get("caller_name",""),
            "file":e.get("callsite_file",""),"line":e.get("callsite_line",0),
            "callee":e.get("receiver","")+("." if e.get("receiver") else "")+e.get("callee",""),
            "resolution":e.get("resolution",""),
            "why":"dynamic/external/ambiguous call; inspect manually if it is on an entry-to-sink path"})
    return {"schema_version":2,"generated_at":_dt.datetime.now(_dt.timezone.utc).isoformat(),
        "sources":sources,"sinks":[sink_edge_to_obj(e) for e in sink_edges],"guards":guards,
        "entry_to_sink_paths":attack_paths,"sink_backtraces":sink_backtraces,"open_edges":open_edges,
        "notes":["This is a structural skeleton, not a taint proof.",
            "A finding still requires reading the code and proving attacker-controlled data reaches the sink without adequate sanitization/authorization."]}

def route_risk_hints(ep,paths):
    hints=[]; method=(ep.get("method") or "").upper(); path=ep.get("path") or ""
    if method in STATE_CHANGING: hints.append("state-changing-route")
    if re.search(r"[:{<]\s*\w*id\w*[}>]?|/:\w*id\w*|/\{\w*id\w*\}",path,re.I): hints.append("id-param-ownership-check-needed")
    if re.search(r"/(admin|internal|manage|root|superuser)\b",path,re.I): hints.append("admin-or-internal-route")
    cats=sorted({p.get("sink",{}).get("category","") for p in paths if p.get("sink",{}).get("category")})
    for c in cats[:8]: hints.append(f"reaches-{c}-sink")
    return hints

def build_proof_ledger(entry_points,dataflow):
    paths_by_entry=collections.defaultdict(list)
    for p in dataflow.get("entry_to_sink_paths",[]):
        ep=p.get("entry",{})
        key=f"{ep.get('file','')}:{ep.get('line',0)}:{ep.get('method','')}:{ep.get('path','')}"
        paths_by_entry[key].append(p)
    route_units=[]
    for ep in entry_points:
        key=f"{ep.get('file','')}:{ep.get('line',0)}:{ep.get('method','')}:{ep.get('path','')}"
        route_units.append({"unit_id":f"route:{sha1_short(key)}","type":"route","status":"pending",
            "method":ep.get("method",""),"path":ep.get("path",""),"file":ep.get("file",""),"line":ep.get("line",0),
            "handler":ep.get("handler",""),"handler_symbol":ep.get("handler_symbol",""),
            "risk_hints":route_risk_hints(ep,paths_by_entry.get(key,[])),
            "reachable_sinks":[p.get("sink",{}) for p in paths_by_entry.get(key,[])[:40]],
            "commands":{"forward_trace":f"python3 .agents/skills/source-model/scripts/callgraph.py --forward '{ep.get('handler_symbol','')}' --depth {MAX_BFS_DEPTH}" if ep.get("handler_symbol") else ""},
            "checklist":{"authn_checked":False,"authz_checked":False,"ownership_or_tenant_checked":False,
                "input_validation_checked":False,"all_reachable_sinks_accounted_for":False},
            "verdict":"unknown","evidence":[],"notes":[]})
    sink_units=[]
    for s in dataflow.get("sinks",[]):
        key=f"{s.get('file','')}:{s.get('line',0)}:{s.get('callee','')}"
        sink_units.append({"unit_id":f"sink:{sha1_short(key)}","type":"sink","status":"pending",
            "category":s.get("category",""),"callee":s.get("callee",""),"file":s.get("file",""),"line":s.get("line",0),
            "caller_symbol":s.get("caller_symbol",""),
            "commands":{"backward_trace":f"python3 .agents/skills/source-model/scripts/callgraph.py --trace '{s.get('callee','')}' --depth {MAX_BFS_DEPTH}"},
            "checklist":{"source_reached":False,"sanitizers_checked":False,"exploitability_checked":False,
                "false_positive_reason_recorded_if_safe":False},
            "verdict":"unknown","evidence":[],"notes":[]})
    return {"schema_version":2,"generated_at":_dt.datetime.now(_dt.timezone.utc).isoformat(),
        "route_units":route_units,"sink_units":sink_units,"open_edges":dataflow.get("open_edges",[]),
        "safe_summaries":[],
        "rules":["Mark a unit done only after recording either a finding id or a concrete safe reason.",
            "For routes, account for authn/authz/ownership and all reachable sinks on the path.",
            "For sinks, trace backward to attacker input or record why no attacker-controlled source reaches it."]}

def write_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("w",encoding="utf-8") as f: json.dump(obj,f,indent=2,ensure_ascii=False)

def normalize_symbol_spans(symbols,line_count):
    uniq={}
    for s in symbols:
        s["start_line"]=max(1,int(s.get("start_line",1)))
        s["end_line"]=min(line_count,max(s["start_line"],int(s.get("end_line",s["start_line"]))))
        uniq.setdefault(s["id"],s)
    out=list(uniq.values()); out.sort(key=lambda s:(s["start_line"],-(s["end_line"]-s["start_line"]),s["kind"]))
    return out

def read_git_commit(root):
    head=Path(root)/".git"/"HEAD"
    try:
        if not head.exists(): return ""
        val=head.read_text(encoding="utf-8",errors="replace").strip()
        if val.startswith("ref:"):
            ref=val.split(None,1)[1]; p=Path(root)/".git"/ref
            if p.exists(): return p.read_text(encoding="utf-8",errors="replace").strip()[:40]
        return val[:40]
    except Exception: return ""

# A whole-repo model of a huge app (e.g. GitLab) blows up to GB-scale because the BFS path
# enumeration (entry_to_sink_paths + sink_backtraces) is roughly paths*depth and the resulting
# JSON can't be loaded back. So we support two scales, following the V2 design but bounding it:
#   --graph-only : symbols + call_graph + entry_points ONLY (no dataflow/proof_ledger). This is
#                  the light GLOBAL INDEX over the whole repo - lets you resolve cross-module
#                  calls and locate entry points without GB output.
#   <module path>: run on ONE module (a subdir) to get the FULL set (dataflow + proof_ledger)
#                  scoped to that module - small and deep. This is what A/B run per coverage --next.
# A repo over TF_GRAPH_ONLY_FILES files auto-falls back to graph-only (with a warning) so a
# naive whole-repo run never OOMs; pass --force-paths to override.
GRAPH_ONLY_FILES=int(os.environ.get("TF_GRAPH_ONLY_FILES","4000"))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("target"); ap.add_argument("-o","--out",default="workspace/CODE_MODEL.json")
    ap.add_argument("--no-artifacts",action="store_true")
    ap.add_argument("--graph-only",action="store_true",
        help="symbols+call_graph+entry_points only; skip dataflow/proof_ledger (global index for huge repos)")
    ap.add_argument("--force-paths",action="store_true",
        help="build full dataflow/proof_ledger even if the repo exceeds the auto graph-only threshold")
    args=ap.parse_args()
    root=os.path.abspath(args.target)
    if not os.path.isdir(root): sys.exit(f"target not a directory: {root}")
    out_path=Path(args.out); workspace=out_path.parent if out_path.parent!=Path("") else Path(".")
    files=[]; langs=set(); file_infos=[]; all_symbols=[]; all_imports=[]
    for full in iter_source_files(root):
        rel=os.path.relpath(full,root).replace("\\","/"); lang=detect_language(full) or "unknown"
        langs.add(lang); files.append(rel)
        try: text=open(full,"rb").read().decode("utf-8","replace")
        except Exception: continue
        line_count=max(1,text.count("\n")+1)
        symbols=[add_module_symbol(rel,lang,line_count)]
        extracted,imports=extract_symbols_and_imports(rel,lang,text)
        symbols.extend(extracted); symbols=normalize_symbol_spans(symbols,line_count)
        file_infos.append({"rel":rel,"lang":lang,"text":text,"symbols":symbols,"imports":imports})
        all_symbols.extend(symbols); all_imports.extend(imports)
    # decide scale: explicit --graph-only, or auto when the repo is huge and not --force-paths
    graph_only=args.graph_only or (len(files)>GRAPH_ONLY_FILES and not args.force_paths)
    if graph_only and not args.graph_only:
        print(f"[build_code_model] {len(files)} files > {GRAPH_ONLY_FILES}: auto graph-only "
              f"(global index; no dataflow/proof_ledger). Build per-module for full paths, "
              f"or pass --force-paths to override.", file=sys.stderr)
    resolver=Resolver(all_symbols,all_imports,files)
    all_callsites=[]; all_sources=[]; all_guards=[]; entry_points=[]
    for info in file_infos:
        all_callsites.extend(extract_callsites(info))
        if not graph_only:
            sources,guards=extract_sources_guards(info)
            all_sources.extend(sources); all_guards.extend(guards)
    symbols_by_id={s["id"]:s for s in all_symbols}
    # In graph-only on a huge repo the call_graph (1.7M edges / 1.7GB on GitLab) is unreadable
    # whole-repo AND we deliberately block whole-repo edge queries - so building/writing it is
    # pure waste. Skip it entirely; per-module full builds produce the edges that actually get
    # used. We still scan callsites for the stats count, but don't materialize edges.
    if graph_only:
        call_graph=[]
        # cheap edge count for stats without building/keeping edge objects
        _edge_count=len(all_callsites)
    else:
        call_graph=build_call_graph(all_callsites,resolver,symbols_by_id)
        _edge_count=len(call_graph)
    for info in file_infos: entry_points.extend(extract_entry_points(info,resolver))
    # In graph-only on a huge repo the call_graph itself (1.7M edges on GitLab) is what blows
    # memory when loaded back. So we keep it OUT of the main model and write it to a separate
    # call_graph.json. The main CODE_MODEL.json then holds only files + entry_points + refs,
    # staying small enough to load. Tools that need edges read call_graph.json (and on a repo
    # this size should do it per-module, not whole-repo).
    call_graph_in_model = call_graph
    call_graph_ref = ""
    if graph_only:
        dataflow={"schema_version":2,"graph_only":True,"sources":[],"sinks":[],"guards":[],
            "entry_to_sink_paths":[],"sink_backtraces":[],"open_edges":[],
            "notes":["graph-only build: dataflow/paths AND call_graph skipped (repo too large or "
                     "--graph-only). Build a single module for full call_graph + dataflow + proof_ledger."]}
        ledger={"schema_version":2,"graph_only":True,"route_units":[],"sink_units":[],
            "open_edges":[],"safe_summaries":[],
            "rules":["graph-only: no proof units. Build per-module to get route/sink units."]}
        call_graph_in_model=[]   # no edges in the global index at all
    else:
        dataflow=build_dataflow(all_symbols,call_graph,entry_points,all_sources,all_guards)
        ledger=build_proof_ledger(entry_points,dataflow)
    symbols_ref=str(workspace/"symbols.json"); callsites_ref=str(workspace/"callsites.json")
    dataflow_ref=str(workspace/"dataflow.json"); proof_ledger_ref=str(workspace/"proof_ledger.json")
    route_map_seed=[{"method":e.get("method",""),"path":e.get("path",""),"handler":e.get("handler",""),
        "file":e.get("file",""),"line":e.get("line",0),"handler_symbol":e.get("handler_symbol","")} for e in entry_points]
    stats={"files":len(files),"symbols":len(all_symbols),"mode":"graph-only" if graph_only else "full",
        "functions_or_methods":sum(1 for s in all_symbols if s.get("kind") in {"function","method"}),
        "entry_points":len(entry_points),"callsites":len(all_callsites),"call_edges":_edge_count,
        "resolved_edges":sum(1 for e in call_graph if e.get("callee_symbol")),
        "sink_edges":sum(1 for e in call_graph if e.get("sink_category")),
        "sources":len(all_sources),"guards":len(all_guards),
        "entry_to_sink_paths":len(dataflow.get("entry_to_sink_paths",[])),"open_edges":len(dataflow.get("open_edges",[]))}
    model={"target":{"name":os.path.basename(root.rstrip(os.sep)),"languages":sorted(l for l in langs if l),
        "root":args.target,"commit":read_git_commit(root)},
        "structural":{"schema_version":2,"mode":"graph-only" if graph_only else "full",
        "files":sorted(files),"entry_points":entry_points,
        "call_graph":call_graph_in_model,"call_graph_ref":call_graph_ref,
        "symbols_ref":symbols_ref,"callsites_ref":callsites_ref,
        "dataflow_ref":dataflow_ref,"proof_ledger_ref":proof_ledger_ref,"cfg_ref":"","stats":stats},
        "comprehension":{"service_identity":{"domain":"","purpose":"","sensitive_data":[]},
        "route_map":route_map_seed,"feature_flows":[],
        "permission_model":{"roles":[],"auth_mechanism":"","authz_locations":[]},
        "user_journeys":[],"trust_boundaries":[]},
        "generated_at":_dt.datetime.now(_dt.timezone.utc).isoformat()}
    write_json(out_path,model)
    # Artifact naming: derive from the model file's stem so a per-module build
    # (-o workspace/cm/api.json) writes api.symbols.json / api.dataflow.json /
    # api.proof_ledger.json NEXT TO IT, instead of clobbering the global
    # workspace/symbols.json etc. The default global build (-o workspace/CODE_MODEL.json)
    # keeps the canonical plain names so downstream defaults still resolve.
    stem = out_path.stem
    is_canonical = (stem == "CODE_MODEL")
    def artifact(name):  # name like "symbols.json"
        if is_canonical:
            return workspace / name
        return out_path.with_name(f"{stem}.{name}")
    # rewrite the refs in the model to point at the actual artifact paths, then re-write model
    model["structural"]["symbols_ref"]   = str(artifact("symbols.json"))
    model["structural"]["callsites_ref"] = str(artifact("callsites.json"))
    model["structural"]["dataflow_ref"]  = str(artifact("dataflow.json"))
    model["structural"]["proof_ledger_ref"] = str(artifact("proof_ledger.json"))
    if call_graph_ref:
        call_graph_ref = str(artifact("call_graph.json"))
        model["structural"]["call_graph_ref"] = call_graph_ref
    write_json(out_path,model)
    if call_graph_ref:
        write_json(Path(call_graph_ref),{"schema_version":2,"call_graph":call_graph,
            "note":"edges split out of CODE_MODEL.json (graph-only). On a huge repo do not load this whole-repo; build per-module."})
    write_json(artifact("_model_stats.json") if not is_canonical else workspace/"_model_stats.json",
        {"target":model["target"]["name"],"mode":stats["mode"],"stats":stats,"generated_at":model["generated_at"]})
    if not args.no_artifacts:
        write_json(artifact("symbols.json"),{"schema_version":2,"symbols":all_symbols,"imports":all_imports})
        write_json(artifact("callsites.json"),{"schema_version":2,"callsites":all_callsites})
        write_json(artifact("dataflow.json"),dataflow)
        write_json(artifact("proof_ledger.json"),ledger)
    print("[build_code_model] "
        f"mode={stats['mode']} files={stats['files']} symbols={stats['symbols']} funcs={stats['functions_or_methods']} "
        f"entry_points={stats['entry_points']} callsites={stats['callsites']} "
        f"edges={stats['call_edges']} resolved={stats['resolved_edges']} sinks={stats['sink_edges']} "
        f"paths={stats['entry_to_sink_paths']} open_edges={stats['open_edges']}")
    print(f"[build_code_model] wrote {args.out}")

if __name__=="__main__":
    main()