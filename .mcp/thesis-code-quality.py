#!/usr/bin/env python3
"""
MCP Server: Thesis Code Quality
Provides tools for code analysis, testing, and quality checks.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# Simple MCP protocol implementation
def send_response(result: Any):
    """Send MCP response."""
    response = {"jsonrpc": "2.0", "result": result}
    print(json.dumps(response), flush=True)


def send_error(code: int, message: str):
    """Send MCP error response."""
    error = {"jsonrpc": "2.0", "error": {"code": code, "message": message}}
    print(json.dumps(error), flush=True)


def run_command(args: list[str], cwd: str = None) -> tuple[bool, str]:
    """Run command and return success status and output."""
    try:
        result = subprocess.run(
            args,
            cwd=cwd or "/home/ishaq2321/Desktop/Thesis",
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


# =============================================================================
# Code Analysis Tools
# =============================================================================

def find_function(function_name: str, directory: str = "backend") -> dict:
    """Find function definition in codebase."""
    project_root = Path("/home/ishaq2321/Desktop/Thesis")
    search_dir = project_root / directory
    
    results = []
    
    for py_file in search_dir.rglob("*.py"):
        try:
            with open(py_file) as f:
                content = f.read()
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name == function_name:
                        results.append({
                            "file": str(py_file.relative_to(project_root)),
                            "line": node.lineno,
                            "name": node.name,
                            "args": [arg.arg for arg in node.args.args],
                            "isAsync": isinstance(node, ast.AsyncFunctionDef)
                        })
                    elif isinstance(node, ast.ClassDef):
                        for item in node.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                if item.name == function_name:
                                    results.append({
                                        "file": str(py_file.relative_to(project_root)),
                                        "line": item.lineno,
                                        "name": item.name,
                                        "class": node.name,
                                        "args": [arg.arg for arg in item.args.args],
                                        "isAsync": isinstance(item, ast.AsyncFunctionDef)
                                    })
        except Exception:
            continue
    
    return {
        "function": function_name,
        "found": len(results),
        "results": results
    }


def list_functions_in_file(file_path: str) -> dict:
    """List all functions in a file."""
    project_root = Path("/home/ishaq2321/Desktop/Thesis")
    full_path = project_root / file_path
    
    if not full_path.exists():
        return {"error": f"File not found: {file_path}"}
    
    try:
        with open(full_path) as f:
            content = f.read()
            tree = ast.parse(content)
        
        functions = []
        classes = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append({
                    "name": node.name,
                    "line": node.lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "isAsync": isinstance(node, ast.AsyncFunctionDef)
                })
            elif isinstance(node, ast.ClassDef):
                methods = []
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.append({
                            "name": item.name,
                            "line": item.lineno,
                            "args": [arg.arg for arg in item.args.args],
                            "isAsync": isinstance(item, ast.AsyncFunctionDef)
                        })
                classes.append({
                    "name": node.name,
                    "line": node.lineno,
                    "methods": methods
                })
        
        return {
            "file": file_path,
            "functions": functions,
            "classes": classes,
            "totalFunctions": len(functions),
            "totalClasses": len(classes)
        }
    
    except Exception as e:
        return {"error": str(e)}


def check_naming_conventions(directory: str = "backend") -> dict:
    """Check if code follows camelCase/snake_case conventions."""
    project_root = Path("/home/ishaq2321/Desktop/Thesis")
    search_dir = project_root / directory
    
    violations = []
    
    for py_file in search_dir.rglob("*.py"):
        try:
            with open(py_file) as f:
                content = f.read()
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    # Check functions (should be camelCase)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        name = node.name
                        if name.startswith("_"):
                            continue
                        if "_" in name and not name.isupper():
                            violations.append({
                                "file": str(py_file.relative_to(project_root)),
                                "line": node.lineno,
                                "type": "function",
                                "name": name,
                                "issue": "Use camelCase for functions"
                            })
                    
                    # Check classes (should be PascalCase)
                    elif isinstance(node, ast.ClassDef):
                        name = node.name
                        if "_" in name:
                            violations.append({
                                "file": str(py_file.relative_to(project_root)),
                                "line": node.lineno,
                                "type": "class",
                                "name": name,
                                "issue": "Use PascalCase for classes"
                            })
        except Exception:
            continue
    
    return {
        "directory": directory,
        "violations": violations,
        "count": len(violations),
        "status": "pass" if len(violations) == 0 else "fail"
    }


def find_dead_code(directory: str = "backend") -> dict:
    """Find potentially unused functions and imports."""
    project_root = Path("/home/ishaq2321/Desktop/Thesis")
    search_dir = project_root / directory
    
    defined_functions = set()
    called_functions = set()
    
    # First pass: collect all defined functions
    for py_file in search_dir.rglob("*.py"):
        try:
            with open(py_file) as f:
                tree = ast.parse(f.read())
                
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if not node.name.startswith("_"):
                            defined_functions.add(node.name)
        except Exception:
            continue
    
    # Second pass: collect all function calls
    for py_file in search_dir.rglob("*.py"):
        try:
            with open(py_file) as f:
                tree = ast.parse(f.read())
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            called_functions.add(node.func.id)
                        elif isinstance(node.func, ast.Attribute):
                            called_functions.add(node.func.attr)
        except Exception:
            continue
    
    # Find potentially unused functions
    unused = defined_functions - called_functions
    
    return {
        "directory": directory,
        "definedFunctions": len(defined_functions),
        "calledFunctions": len(called_functions),
        "potentiallyUnused": sorted(list(unused)),
        "count": len(unused)
    }


# =============================================================================
# Testing Tools
# =============================================================================

def run_tests(test_path: str = "tests/", coverage: bool = False) -> dict:
    """Run pytest with optional coverage."""
    args = ["pytest", test_path, "-v", "--tb=short"]
    
    if coverage:
        args.extend(["--cov=backend", "--cov-report=term-missing"])
    
    success, output = run_command(args)
    
    # Parse output for statistics
    lines = output.split("\n")
    stats = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    
    for line in lines:
        if "passed" in line or "failed" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if "passed" in part and i > 0:
                    try:
                        stats["passed"] = int(parts[i-1])
                    except ValueError:
                        pass
                elif "failed" in part and i > 0:
                    try:
                        stats["failed"] = int(parts[i-1])
                    except ValueError:
                        pass
    
    return {
        "testPath": test_path,
        "success": success,
        "statistics": stats,
        "output": output[-2000:]  # Last 2000 chars
    }


def check_test_coverage(file_path: str) -> dict:
    """Check test coverage for a specific file."""
    args = ["pytest", f"--cov={file_path}", "--cov-report=json", "-q"]
    success, output = run_command(args)
    
    # Try to read coverage.json
    coverage_file = Path("/home/ishaq2321/Desktop/Thesis/coverage.json")
    if coverage_file.exists():
        with open(coverage_file) as f:
            coverage_data = json.load(f)
            
            file_coverage = coverage_data.get("files", {}).get(file_path, {})
            
            return {
                "file": file_path,
                "coverage": file_coverage.get("summary", {}),
                "missingLines": file_coverage.get("missing_lines", []),
                "excludedLines": file_coverage.get("excluded_lines", [])
            }
    
    return {
        "file": file_path,
        "error": "Coverage data not available",
        "output": output
    }


def check_for_errors() -> dict:
    """Run linting and type checking to find errors."""
    results = {}
    
    # Run flake8
    success, output = run_command(["flake8", "backend/", "--count", "--statistics"])
    results["flake8"] = {
        "success": success,
        "output": output[:1000]
    }
    
    # Run mypy (if available)
    success, output = run_command(["mypy", "backend/", "--ignore-missing-imports"])
    results["mypy"] = {
        "success": success,
        "output": output[:1000]
    }
    
    return results


# =============================================================================
# Quality Checks
# =============================================================================

def validate_thesis_conventions() -> dict:
    """Validate code follows thesis conventions (from copilot-instructions.md)."""
    issues = []
    
    # Check naming conventions
    naming_result = check_naming_conventions()
    if naming_result["count"] > 0:
        issues.append({
            "category": "Naming Conventions",
            "count": naming_result["count"],
            "violations": naming_result["violations"][:5]  # First 5
        })
    
    # Check for dead code
    dead_code_result = find_dead_code()
    if dead_code_result["count"] > 0:
        issues.append({
            "category": "Dead Code",
            "count": dead_code_result["count"],
            "potentiallyUnused": dead_code_result["potentiallyUnused"][:10]
        })
    
    # Check test coverage
    test_result = run_tests()
    if test_result["statistics"]["failed"] > 0:
        issues.append({
            "category": "Failing Tests",
            "count": test_result["statistics"]["failed"],
            "passed": test_result["statistics"]["passed"]
        })
    
    return {
        "status": "pass" if len(issues) == 0 else "fail",
        "issueCount": len(issues),
        "issues": issues,
        "timestamp": subprocess.check_output(["date", "+%Y-%m-%d %H:%M:%S"]).decode().strip()
    }


# =============================================================================
# MCP Tool Handlers
# =============================================================================

TOOLS = {
    "find_function": {
        "description": "Find function definition in codebase (returns file, line, args)",
        "parameters": {
            "function_name": {"type": "string", "required": True},
            "directory": {"type": "string", "default": "backend"}
        }
    },
    "list_functions_in_file": {
        "description": "List all functions and classes in a file",
        "parameters": {
            "file_path": {"type": "string", "required": True}
        }
    },
    "check_naming_conventions": {
        "description": "Check if code follows camelCase/snake_case conventions",
        "parameters": {
            "directory": {"type": "string", "default": "backend"}
        }
    },
    "find_dead_code": {
        "description": "Find potentially unused functions and code",
        "parameters": {
            "directory": {"type": "string", "default": "backend"}
        }
    },
    "run_tests": {
        "description": "Run pytest with optional coverage analysis",
        "parameters": {
            "test_path": {"type": "string", "default": "tests/"},
            "coverage": {"type": "boolean", "default": False}
        }
    },
    "check_test_coverage": {
        "description": "Check test coverage for a specific file",
        "parameters": {
            "file_path": {"type": "string", "required": True}
        }
    },
    "check_for_errors": {
        "description": "Run linting (flake8) and type checking (mypy) to find errors",
        "parameters": {}
    },
    "validate_thesis_conventions": {
        "description": "Validate code follows thesis conventions (naming, no dead code, tests passing)",
        "parameters": {}
    }
}


def handle_tool_call(tool_name: str, params: dict) -> dict:
    """Handle MCP tool call."""
    if tool_name == "find_function":
        return find_function(params["function_name"], params.get("directory", "backend"))
    elif tool_name == "list_functions_in_file":
        return list_functions_in_file(params["file_path"])
    elif tool_name == "check_naming_conventions":
        return check_naming_conventions(params.get("directory", "backend"))
    elif tool_name == "find_dead_code":
        return find_dead_code(params.get("directory", "backend"))
    elif tool_name == "run_tests":
        return run_tests(params.get("test_path", "tests/"), params.get("coverage", False))
    elif tool_name == "check_test_coverage":
        return check_test_coverage(params["file_path"])
    elif tool_name == "check_for_errors":
        return check_for_errors()
    elif tool_name == "validate_thesis_conventions":
        return validate_thesis_conventions()
    else:
        return {"error": f"Unknown tool: {tool_name}"}


# =============================================================================
# Main MCP Server Loop
# =============================================================================

def main():
    """MCP server main loop."""
    for line in sys.stdin:
        try:
            request = json.loads(line)
            
            if request.get("method") == "tools/list":
                send_response({"tools": TOOLS})
            
            elif request.get("method") == "tools/call":
                tool_name = request["params"]["name"]
                params = request["params"].get("arguments", {})
                result = handle_tool_call(tool_name, params)
                send_response(result)
            
            else:
                send_error(-32601, "Method not found")
        
        except Exception as e:
            send_error(-32603, f"Internal error: {str(e)}")


if __name__ == "__main__":
    main()
