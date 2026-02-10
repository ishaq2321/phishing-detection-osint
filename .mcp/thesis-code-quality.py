#!/usr/bin/env python3
"""
MCP Server: Thesis Code Quality
Code analysis, testing, and quality checks.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = "/home/ishaq2321/Desktop/Thesis"


def send_response(request_id, result):
    msg = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def send_error(request_id, code, message):
    msg = json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def run_cmd(args, cwd=None):
    try:
        r = subprocess.run(args, cwd=cwd or PROJECT_ROOT, capture_output=True, text=True, timeout=120)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


# =============================================================================
# Code Analysis
# =============================================================================

def find_function(function_name, directory="backend"):
    search_dir = Path(PROJECT_ROOT) / directory
    results = []
    for py_file in search_dir.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
                    results.append({
                        "file": str(py_file.relative_to(PROJECT_ROOT)),
                        "line": node.lineno,
                        "args": [a.arg for a in node.args.args],
                        "isAsync": isinstance(node, ast.AsyncFunctionDef)
                    })
                elif isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == function_name:
                            results.append({
                                "file": str(py_file.relative_to(PROJECT_ROOT)),
                                "line": item.lineno, "class": node.name,
                                "args": [a.arg for a in item.args.args],
                                "isAsync": isinstance(item, ast.AsyncFunctionDef)
                            })
        except Exception:
            continue
    return {"function": function_name, "found": len(results), "results": results}


def list_functions_in_file(file_path):
    full = Path(PROJECT_ROOT) / file_path
    if not full.exists():
        return {"error": f"File not found: {file_path}"}
    try:
        tree = ast.parse(full.read_text())
        fns, classes = [], []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fns.append({"name": node.name, "line": node.lineno,
                            "args": [a.arg for a in node.args.args],
                            "isAsync": isinstance(node, ast.AsyncFunctionDef)})
            elif isinstance(node, ast.ClassDef):
                methods = []
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.append({"name": item.name, "line": item.lineno,
                                        "args": [a.arg for a in item.args.args],
                                        "isAsync": isinstance(item, ast.AsyncFunctionDef)})
                classes.append({"name": node.name, "line": node.lineno, "methods": methods})
        return {"file": file_path, "functions": fns, "classes": classes}
    except Exception as e:
        return {"error": str(e)}


def find_dead_code(directory="backend"):
    search_dir = Path(PROJECT_ROOT) / directory
    defined, called = set(), set()
    for py_file in search_dir.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                    defined.add(node.name)
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        called.add(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        called.add(node.func.attr)
        except Exception:
            continue
    unused = sorted(defined - called)
    return {"defined": len(defined), "called": len(called), "potentiallyUnused": unused, "count": len(unused)}


# =============================================================================
# Testing
# =============================================================================

def run_tests(test_path="tests/", verbose=False):
    args = ["python3", "-m", "pytest", test_path, "-q", "--tb=line"]
    if verbose:
        args = ["python3", "-m", "pytest", test_path, "-v", "--tb=short"]
    ok, out = run_cmd(args)
    lines = out.strip().split("\n")
    summary = lines[-1] if lines else ""
    return {"testPath": test_path, "success": ok, "summary": summary, "output": out[-3000:]}


def run_single_test(test_path):
    ok, out = run_cmd(["python3", "-m", "pytest", test_path, "-v", "--tb=short"])
    return {"test": test_path, "success": ok, "output": out[-3000:]}


def check_for_errors():
    results = {}
    ok, out = run_cmd(["python3", "-m", "py_compile", "backend/main.py"])
    results["syntax"] = {"success": ok, "output": out[:500]}
    ok, out = run_cmd(["python3", "-c", "import backend.main; print('All imports OK')"])
    results["imports"] = {"success": ok, "output": out[:500]}
    return results


# =============================================================================
# Tool definitions (MCP spec with inputSchema)
# =============================================================================

TOOLS = [
    {"name": "find_function",
     "description": "Find where a function is defined in the codebase. Returns file, line, args.",
     "inputSchema": {"type": "object", "properties": {
         "function_name": {"type": "string", "description": "Function name to find"},
         "directory": {"type": "string", "description": "Directory to search", "default": "backend"}},
         "required": ["function_name"]}},
    {"name": "list_functions_in_file",
     "description": "List all functions and classes in a Python file.",
     "inputSchema": {"type": "object", "properties": {
         "file_path": {"type": "string", "description": "Relative file path"}},
         "required": ["file_path"]}},
    {"name": "find_dead_code",
     "description": "Find potentially unused functions in the codebase.",
     "inputSchema": {"type": "object", "properties": {
         "directory": {"type": "string", "description": "Directory to scan", "default": "backend"}}}},
    {"name": "run_tests",
     "description": "Run pytest on the project. Returns pass/fail summary.",
     "inputSchema": {"type": "object", "properties": {
         "test_path": {"type": "string", "description": "Test path", "default": "tests/"},
         "verbose": {"type": "boolean", "description": "Verbose output", "default": False}}}},
    {"name": "run_single_test",
     "description": "Run a single test file or test class/method.",
     "inputSchema": {"type": "object", "properties": {
         "test_path": {"type": "string", "description": "Test path (e.g. tests/unit/test_scorer.py::TestDetermineRiskLevel)"}},
         "required": ["test_path"]}},
    {"name": "check_for_errors",
     "description": "Check for syntax and import errors in backend code.",
     "inputSchema": {"type": "object", "properties": {}}}
]


# =============================================================================
# Tool dispatcher
# =============================================================================

def call_tool(name, args):
    dispatch = {
        "find_function": lambda: find_function(args["function_name"], args.get("directory", "backend")),
        "list_functions_in_file": lambda: list_functions_in_file(args["file_path"]),
        "find_dead_code": lambda: find_dead_code(args.get("directory", "backend")),
        "run_tests": lambda: run_tests(args.get("test_path", "tests/"), args.get("verbose", False)),
        "run_single_test": lambda: run_single_test(args["test_path"]),
        "check_for_errors": lambda: check_for_errors(),
    }
    fn = dispatch.get(name)
    if fn:
        return fn()
    raise ValueError(f"Unknown tool: {name}")


# =============================================================================
# MCP Server main loop
# =============================================================================

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            rid = req.get("id")
            method = req.get("method")

            if method == "initialize":
                send_response(rid, {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "thesis-code-quality", "version": "1.0.0"}
                })

            elif method == "notifications/initialized":
                pass

            elif method == "tools/list":
                send_response(rid, {"tools": TOOLS})

            elif method == "tools/call":
                name = req["params"]["name"]
                args = req["params"].get("arguments", {})
                result = call_tool(name, args)
                send_response(rid, {"content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]})

            elif method == "ping":
                send_response(rid, {})

            else:
                send_error(rid, -32601, f"Method not found: {method}")

        except Exception as e:
            rid_val = None
            try:
                rid_val = req.get("id")
            except Exception:
                pass
            send_error(rid_val, -32603, str(e))


if __name__ == "__main__":
    main()
