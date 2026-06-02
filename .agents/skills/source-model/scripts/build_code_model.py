#!/usr/bin/env python3
"""
build_code_model.py - structural-layer extractor for the source-model stage.

Language-agnostic. Walks a target source tree and emits the `structural` half of
CODE_MODEL.json: files, entry_points (route/handler heuristics), and a coarse
call_graph. The `comprehension` half is left as an empty scaffold for the LLM to
fill (see ../SKILL.md). This script produces FACTS only; meaning is the LLM's job.

tree-sitter (via tree-sitter-language-pack) is used when available to extract
function definitions and call edges precisely. If it is not installed, the script
degrades to regex heuristics so it always produces a valid seed.

Usage:
    build_code_model.py <target_dir> [-o workspace/CODE_MODEL.json]
"""
import argparse, json, os, re, sys, datetime

EXT_LANG = {
    ".py":"python", ".js":"javascript", ".jsx":"javascript", ".ts":"typescript",
    ".tsx":"tsx", ".java":"java", ".go":"go", ".rb":"ruby", ".php":"php",
    ".cs":"c_sharp", ".c":"c", ".cpp":"cpp", ".cc":"cpp", ".rs":"rust",
    ".kt":"kotlin", ".scala":"scala", ".swift":"swift",
}
SKIP_DIRS = {".git","node_modules","vendor","dist","build","__pycache__",
             ".venv","venv","target",".next","coverage"}

# Route / entry-point heuristics, language-agnostic (regex on source).
ROUTE_PATTERNS = [
    # python: @app.route("/x"), @router.get("/x"), @bp.post(...)
    (r'@[\w.]+\.(route|get|post|put|patch|delete)\(\s*[\'"]([^\'"]+)[\'"]', "http-route"),
    # express/koa/fastify: app.get("/x", ...), router.post('/x', ...)
    (r'\b\w+\.(get|post|put|patch|delete|use|all)\(\s*[\'"]([^\'"]+)[\'"]', "http-route"),
    # spring: @GetMapping("/x"), @RequestMapping(...)
    (r'@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*[\'"]?([^\'")]+)?', "http-route"),
    # go: r.HandleFunc("/x", ...), mux.Get("/x", ...)
    (r'\b\w+\.(HandleFunc|Handle|Get|Post|Put|Delete)\(\s*[\'"]([^\'"]+)[\'"]', "http-route"),
]

def detect_language(path):
    return EXT_LANG.get(os.path.splitext(path)[1].lower())

def iter_source_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if detect_language(full):
                yield full

def try_tree_sitter():
    try:
        from tree_sitter_language_pack import get_parser  # noqa
        return get_parser
    except Exception:
        return None

def ts_extract(get_parser, lang, src_bytes):
    """Return (functions, call_names) using tree-sitter when possible."""
    funcs, calls = [], []
    try:
        parser = get_parser(lang)
    except Exception:
        # e.g. Rust-backed language-pack failing to download a grammar offline.
        return funcs, calls
    # parse() API differs across builds: classic tree-sitter wants bytes, the
    # newer Rust-backed language-pack wants str. Try both; never raise.
    tree = None
    for arg in (src_bytes, src_bytes.decode("utf8", "replace")):
        try:
            tree = parser.parse(arg); break
        except TypeError:
            continue
        except Exception:
            return funcs, calls
    if tree is None:
        return funcs, calls
    def txt(n):
        return src_bytes[n.start_byte:n.end_byte].decode("utf8","replace")
    def walk(node):
        t = node.type
        # ---- function / method definitions (multi-language) ----
        if t in ("function_definition","function_declaration","method_definition",
                 "method_declaration","function_item","func_literal","method"):
            # name field first (PHP/JS/Go expose it); else first identifier-ish child
            nn = node.child_by_field_name("name")
            name = txt(nn) if nn is not None else None
            if name is None:
                for c in node.children:
                    if c.type in ("identifier","field_identifier","property_identifier","name"):
                        name = txt(c); break
            funcs.append({"name": name or "<anon>", "line": node.start_point[0]+1})
        # ---- calls (multi-language incl. PHP) ----
        if t in ("call","call_expression","method_invocation",                 # JS/TS/Java/Py
                 "function_call_expression","member_call_expression",          # PHP func / $o->m()
                 "scoped_call_expression","nullsafe_member_call_expression"):   # PHP C::m() / $o?->m()
            # the callee name: prefer a 'name'/'function' field, else first child
            head = (node.child_by_field_name("name")
                    or node.child_by_field_name("function")
                    or (node.children[0] if node.children else None))
            if head is not None:
                calls.append(txt(head))
        for c in node.children:
            walk(c)
    try:
        walk(tree.root_node)
    except Exception:
        return [], []
    return funcs, calls

_KEYWORDS = {"if","for","while","switch","catch","function","echo","print","return",
             "array","list","isset","empty","unset","new","clone","and","or","not",
             "foreach","elseif","else","do","try","throw","match","fn","use","class",
             "interface","trait","global","static","public","private","protected",
             "const","var","int","string","bool"}
# language-construct / high-risk sinks that aren't normal `name(` calls - captured specially
_CONSTRUCT_SINKS = ("include","include_once","require","require_once","eval")

def regex_extract(text):
    funcs = [{"name": m.group(1), "line": text[:m.start()].count("\n")+1}
             for m in re.finditer(r'\b(?:def|function|func|fn)\s+([A-Za-z_]\w*)', text)]
    # coarse call extraction: bare calls foo(, method calls ->bar( / .bar(, static Cls::baz(
    calls = []
    for m in re.finditer(r'(?:->|::|\.)?\s*([A-Za-z_]\w*)\s*\(', text):
        name = m.group(1)
        if name and name not in _KEYWORDS:
            calls.append(name)
    # include/require/eval are language constructs (often no parens) - capture as sink edges
    for m in re.finditer(r'\b(include|include_once|require|require_once|eval)\b\s*[\(\'"$]', text):
        calls.append(m.group(1))
    return funcs, calls

def find_entry_points(rel, text):
    eps = []
    for pat, kind in ROUTE_PATTERNS:
        for m in re.finditer(pat, text):
            groups = [g for g in m.groups() if g]
            method = groups[0] if groups else ""
            path = groups[-1] if len(groups) > 1 else ""
            eps.append({"kind": kind, "method": method.upper(),
                        "path": path, "handler": "", "file": rel,
                        "line": text[:m.start()].count("\n")+1})
    return eps

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-o","--out", default="workspace/CODE_MODEL.json")
    args = ap.parse_args()

    root = os.path.abspath(args.target)
    if not os.path.isdir(root):
        sys.exit(f"target not a directory: {root}")

    get_parser = try_tree_sitter()
    files, entry_points, langs = [], [], set()
    func_index = {}        # "file::name" -> True, for resolving call edges
    pending_calls = []     # (caller_file, callee_name)

    for full in iter_source_files(root):
        rel = os.path.relpath(full, root)
        lang = detect_language(full); langs.add(lang)
        files.append(rel)
        try:
            data = open(full,"rb").read()
            text = data.decode("utf8","replace")
        except Exception:
            continue
        funcs, calls = ([], [])
        if get_parser:
            funcs, calls = ts_extract(get_parser, lang, data)
        rx_funcs, rx_calls = regex_extract(text)
        if not funcs:                      # ts unavailable/failed for this file
            funcs = rx_funcs
        if not calls:                      # ts gave no calls -> regex backstop
            calls = rx_calls
        for f in funcs:
            func_index.setdefault(f["name"], rel)   # name -> defining file (first wins)
        for c in calls:
            # normalize callee: strip receiver ($obj->, Class::, obj.) and arg paren
            short = re.split(r'->|::|\.', c)[-1].split("(")[0].strip().lstrip("$")
            if short:
                pending_calls.append((rel, short))
        entry_points.extend(find_entry_points(rel, text))

    # known dangerous sinks (built-ins): record their call sites even though they don't
    # resolve to a user-defined function, so backward taint can find every call site.
    SINKS = {
        # SQL / query
        "query","exec","mysqli_query","mysql_query","pg_query","prepare","rawQuery",
        # command
        "system","shell_exec","passthru","proc_open","popen","pcntl_exec",
        # code / eval / deserialize
        "eval","assert","create_function","unserialize","call_user_func","call_user_func_array",
        # file / inclusion
        "include","include_once","require","require_once","file_get_contents","fopen",
        "readfile","file_put_contents","fwrite","move_uploaded_file",
        # SSRF / net
        "curl_exec","fsockopen","get_headers",
    }
    # coarse call graph: resolve callee name to a known function's defining file.
    seen, call_graph = set(), []
    for caller, callee in pending_calls:
        to_file = func_index.get(callee)
        if to_file and to_file != caller:            # cross-file edge to a known function
            edge = (caller, callee, to_file)
        elif callee in SINKS:                         # dangerous built-in call site
            edge = (caller, callee, "<builtin-sink>")
        else:
            continue
        if edge not in seen:
            seen.add(edge)
            call_graph.append({"from": edge[0], "callee": edge[1], "to": edge[2]})

    model = {
        "target": {
            "name": os.path.basename(root),
            "languages": sorted(l for l in langs if l),
            "root": args.target,
            "commit": ""
        },
        "structural": {
            "files": files,
            "entry_points": entry_points,
            "call_graph": call_graph,
            "symbols_ref": "", "cfg_ref": "", "dataflow_ref": ""
        },
        # LLM fills this in the source-model SKILL.md step:
        "comprehension": {
            "service_identity": {"domain":"", "purpose":"", "sensitive_data":[]},
            "route_map": [], "feature_flows": [], "permission_model": {},
            "user_journeys": [], "trust_boundaries": []
        },
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out,"w") as f:
        json.dump(model, f, indent=2)
    print(f"[build_code_model] files={len(files)} "
          f"entry_points={len(entry_points)} call_edges={len(call_graph)} "
          f"langs={sorted(l for l in langs if l)} ts={'on' if get_parser else 'regex-fallback'}")
    print(f"[build_code_model] wrote {args.out}")

if __name__ == "__main__":
    main()