#!/usr/bin/env python3
"""
MCP Server: Thesis Project Manager
Issue tracking, milestone management, and commits.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = "/home/ishaq2321/Desktop/Thesis"
ISSUES_FILE = f"{PROJECT_ROOT}/.mcp/issues.json"


def send_response(request_id, result):
    msg = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def send_error(request_id, code, message):
    msg = json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def run_git(args):
    try:
        r = subprocess.run(["git"] + args, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


def load_issues():
    p = Path(ISSUES_FILE)
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return []


def save_issues(issues):
    with open(ISSUES_FILE, "w") as f:
        json.dump(issues, f, indent=2)


# =============================================================================
# Milestones
# =============================================================================

MILESTONES = {
    "milestone-1": {"title": "Milestone 1: Planning & Design", "deadline": "2025-12-20",
        "deliverables": ["Finalize topic & plan", "Background research", "System design diagrams", "GitLab setup", "Initial prototype"]},
    "milestone-2": {"title": "Milestone 2: Core Implementation", "deadline": "2026-02-20",
        "deliverables": ["Core algorithm/model implementation", "Backend integration", "Dataset collection & preprocessing", "Preliminary tests"]},
    "milestone-3": {"title": "Milestone 3: Integration & Testing", "deadline": "2026-03-25",
        "deliverables": ["UI development & integration", "Performance improvements", "Solid test coverage", "Methodology & results draft"]},
    "milestone-4": {"title": "Milestone 4: Finalization", "deadline": "2026-04-15",
        "deliverables": ["Final implementation", "Complete documentation", "User guide", "Developer docs", "Full thesis draft"]},
    "final-submission": {"title": "Final Submission", "deadline": "2026-05-01",
        "deliverables": ["Official thesis submission", "Minor corrections only"]}
}


def get_current_milestone():
    today = datetime.now().date()
    for mid, data in MILESTONES.items():
        dl = datetime.strptime(data["deadline"], "%Y-%m-%d").date()
        if today <= dl:
            return {"id": mid, "title": data["title"], "deadline": data["deadline"],
                    "daysRemaining": (dl - today).days, "deliverables": data["deliverables"]}
    return {"id": "overdue", "title": "All milestones passed", "daysRemaining": -1}


def list_milestones():
    today = datetime.now().date()
    result = []
    for mid, data in MILESTONES.items():
        dl = datetime.strptime(data["deadline"], "%Y-%m-%d").date()
        days = (dl - today).days
        status = "completed" if days < 0 else ("due-today" if days == 0 else ("urgent" if days <= 7 else "upcoming"))
        result.append({"id": mid, "title": data["title"], "deadline": data["deadline"],
                       "daysRemaining": days, "status": status, "deliverables": data["deliverables"]})
    return {"milestones": result, "current": get_current_milestone()}


# =============================================================================
# Issues
# =============================================================================

def list_issues(milestone=None, status="open"):
    issues = load_issues()
    if milestone:
        issues = [i for i in issues if i.get("milestone") == milestone]
    if status != "all":
        issues = [i for i in issues if i.get("status") == status]
    return {"count": len(issues), "issues": issues}


def create_issue(title, description="", milestone=None, labels=None):
    issues = load_issues()
    num = max([i["number"] for i in issues], default=0) + 1
    issue = {"number": num, "title": title, "description": description,
             "milestone": milestone or get_current_milestone()["id"],
             "labels": labels or [], "status": "open",
             "created": datetime.now().isoformat(), "closed": None}
    issues.append(issue)
    save_issues(issues)
    return {"success": True, "issue": issue}


def bulk_create_issues(items):
    results = []
    for item in items:
        r = create_issue(item["title"], item.get("description", ""),
                         item.get("milestone"), item.get("labels"))
        results.append(r["issue"])
    return {"success": True, "created": len(results), "issues": results}


def close_issue(issue_number, comment=None):
    issues = load_issues()
    for issue in issues:
        if issue["number"] == issue_number:
            issue["status"] = "closed"
            issue["closed"] = datetime.now().isoformat()
            if comment:
                issue["closeComment"] = comment
            save_issues(issues)
            return {"success": True, "message": f"Closed issue #{issue_number}"}
    return {"success": False, "error": f"Issue #{issue_number} not found"}


def commit_with_issue(issue_number, message, files=None):
    if files:
        for f in files:
            run_git(["add", f])
    else:
        run_git(["add", "-A"])
    commit_msg = f"Issue #{issue_number}: {message}"
    ok, out = run_git(["commit", "-m", commit_msg])
    if ok:
        _, h = run_git(["rev-parse", "--short", "HEAD"])
        return {"success": True, "commit": h, "message": commit_msg}
    return {"success": False, "error": out}


# =============================================================================
# Tool definitions (MCP spec with inputSchema)
# =============================================================================

TOOLS = [
    {"name": "get_current_milestone", "description": "Get the current thesis milestone based on today's date. Returns milestone title, deadline, days remaining, and deliverables.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_milestones", "description": "List all 5 thesis milestones with deadlines, status, and deliverables.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_issues", "description": "List project issues. Filter by milestone or status.",
     "inputSchema": {"type": "object", "properties": {
         "milestone": {"type": "string", "description": "Filter by milestone ID (e.g. milestone-2)"},
         "status": {"type": "string", "enum": ["open", "closed", "all"], "description": "Filter by status", "default": "open"}}}},
    {"name": "create_issue", "description": "Create a new thesis project issue.",
     "inputSchema": {"type": "object", "properties": {
         "title": {"type": "string", "description": "Issue title"},
         "description": {"type": "string", "description": "Issue description"},
         "milestone": {"type": "string", "description": "Milestone ID"},
         "labels": {"type": "array", "items": {"type": "string"}, "description": "Labels"}},
         "required": ["title"]}},
    {"name": "bulk_create_issues", "description": "Create multiple issues at once from an array.",
     "inputSchema": {"type": "object", "properties": {
         "issues": {"type": "array", "items": {"type": "object", "properties": {
             "title": {"type": "string"}, "description": {"type": "string"},
             "milestone": {"type": "string"}, "labels": {"type": "array", "items": {"type": "string"}}},
             "required": ["title"]}, "description": "Array of issues"}},
         "required": ["issues"]}},
    {"name": "close_issue", "description": "Close an issue with optional comment.",
     "inputSchema": {"type": "object", "properties": {
         "issue_number": {"type": "integer", "description": "Issue number to close"},
         "comment": {"type": "string", "description": "Closing comment"}},
         "required": ["issue_number"]}},
    {"name": "commit_with_issue", "description": "Git commit referencing an issue number.",
     "inputSchema": {"type": "object", "properties": {
         "issue_number": {"type": "integer", "description": "Issue number"},
         "message": {"type": "string", "description": "Commit message"},
         "files": {"type": "array", "items": {"type": "string"}, "description": "Files to stage"}},
         "required": ["issue_number", "message"]}}
]


# =============================================================================
# Tool dispatcher
# =============================================================================

def call_tool(name, args):
    dispatch = {
        "get_current_milestone": lambda: get_current_milestone(),
        "list_milestones": lambda: list_milestones(),
        "list_issues": lambda: list_issues(args.get("milestone"), args.get("status", "open")),
        "create_issue": lambda: create_issue(args["title"], args.get("description", ""), args.get("milestone"), args.get("labels")),
        "bulk_create_issues": lambda: bulk_create_issues(args["issues"]),
        "close_issue": lambda: close_issue(args["issue_number"], args.get("comment")),
        "commit_with_issue": lambda: commit_with_issue(args["issue_number"], args["message"], args.get("files")),
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
                    "serverInfo": {"name": "thesis-project-manager", "version": "1.0.0"}
                })

            elif method == "notifications/initialized":
                pass  # No response for notifications

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
