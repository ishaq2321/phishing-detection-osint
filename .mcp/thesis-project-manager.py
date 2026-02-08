#!/usr/bin/env python3
"""
MCP Server: Thesis Project Manager
Provides tools for issue tracking, milestone management, and commits.
"""

import json
import subprocess
import sys
from datetime import datetime
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


def run_git_command(args: list[str]) -> tuple[bool, str]:
    """Run git command and return success status and output."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd="/home/ishaq2321/Desktop/Thesis",
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


# =============================================================================
# Milestone Management
# =============================================================================

MILESTONES = {
    "milestone-1": {
        "title": "Milestone 1: Planning & Design",
        "deadline": "2025-12-20",
        "deliverables": [
            "Finalize topic & plan",
            "Background research",
            "System design diagrams",
            "GitLab setup",
            "Initial prototype"
        ]
    },
    "milestone-2": {
        "title": "Milestone 2: Core Implementation",
        "deadline": "2026-02-20",
        "deliverables": [
            "Core algorithm/model implementation",
            "Backend integration",
            "Dataset collection & preprocessing",
            "Preliminary tests"
        ]
    },
    "milestone-3": {
        "title": "Milestone 3: Integration & Testing",
        "deadline": "2026-03-25",
        "deliverables": [
            "UI development & integration",
            "Performance improvements",
            "Solid test coverage",
            "Methodology & results draft"
        ]
    },
    "milestone-4": {
        "title": "Milestone 4: Finalization",
        "deadline": "2026-04-15",
        "deliverables": [
            "Final implementation",
            "Complete documentation",
            "User guide",
            "Developer docs",
            "Full thesis draft"
        ]
    },
    "final-submission": {
        "title": "Final Submission",
        "deadline": "2026-05-01",
        "deliverables": [
            "Official thesis submission",
            "Minor corrections only"
        ]
    }
}


def get_current_milestone() -> dict:
    """Determine current milestone based on date."""
    today = datetime.now().date()
    
    for milestone_id, data in MILESTONES.items():
        deadline = datetime.strptime(data["deadline"], "%Y-%m-%d").date()
        if today <= deadline:
            days_remaining = (deadline - today).days
            return {
                "id": milestone_id,
                "title": data["title"],
                "deadline": data["deadline"],
                "daysRemaining": days_remaining,
                "deliverables": data["deliverables"]
            }
    
    return {
        "id": "overdue",
        "title": "Project Overdue",
        "deadline": "2026-05-01",
        "daysRemaining": -1,
        "deliverables": []
    }


def list_milestones() -> dict:
    """List all thesis milestones with status."""
    today = datetime.now().date()
    result = []
    
    for milestone_id, data in MILESTONES.items():
        deadline = datetime.strptime(data["deadline"], "%Y-%m-%d").date()
        days_remaining = (deadline - today).days
        
        if days_remaining < 0:
            status = "overdue" if milestone_id != "final-submission" else "past"
        elif days_remaining == 0:
            status = "due-today"
        elif days_remaining <= 7:
            status = "urgent"
        else:
            status = "upcoming"
        
        result.append({
            "id": milestone_id,
            "title": data["title"],
            "deadline": data["deadline"],
            "daysRemaining": days_remaining,
            "status": status,
            "deliverables": data["deliverables"]
        })
    
    return {"milestones": result, "current": get_current_milestone()}


# =============================================================================
# Issue Management
# =============================================================================

def list_issues(milestone: str = None, status: str = "open") -> dict:
    """List GitHub/GitLab issues."""
    # For GitHub
    args = ["log", "--all", "--grep=^Issue", "--oneline", "-20"]
    success, output = run_git_command(args)
    
    issues = []
    if success and output:
        for line in output.strip().split("\n"):
            if line:
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    issues.append({
                        "commit": parts[0],
                        "message": parts[1]
                    })
    
    return {
        "milestone": milestone,
        "status": status,
        "count": len(issues),
        "issues": issues[:10]  # Return first 10
    }


def create_issue(title: str, description: str, milestone: str = None, labels: list = None) -> dict:
    """Create a new issue (tracked in issues.json)."""
    issues_file = Path("/home/ishaq2321/Desktop/Thesis/.mcp/issues.json")
    
    # Load existing issues
    issues = []
    if issues_file.exists():
        with open(issues_file) as f:
            issues = json.load(f)
    
    # Create new issue
    issue_number = len(issues) + 1
    new_issue = {
        "number": issue_number,
        "title": title,
        "description": description,
        "milestone": milestone or get_current_milestone()["id"],
        "labels": labels or [],
        "status": "open",
        "created": datetime.now().isoformat(),
        "closed": None
    }
    
    issues.append(new_issue)
    
    # Save issues
    with open(issues_file, "w") as f:
        json.dump(issues, f, indent=2)
    
    return {
        "success": True,
        "issue": new_issue,
        "message": f"Created issue #{issue_number}: {title}"
    }


def bulk_create_issues(issues_data: list[dict]) -> dict:
    """Create multiple issues at once."""
    results = []
    
    for issue_data in issues_data:
        result = create_issue(
            title=issue_data["title"],
            description=issue_data.get("description", ""),
            milestone=issue_data.get("milestone"),
            labels=issue_data.get("labels", [])
        )
        results.append(result)
    
    return {
        "success": True,
        "created": len(results),
        "issues": results
    }


def close_issue(issue_number: int, comment: str = None) -> dict:
    """Close an issue."""
    issues_file = Path("/home/ishaq2321/Desktop/Thesis/.mcp/issues.json")
    
    if not issues_file.exists():
        return {"success": False, "error": "No issues file found"}
    
    with open(issues_file) as f:
        issues = json.load(f)
    
    # Find and close issue
    found = False
    for issue in issues:
        if issue["number"] == issue_number:
            issue["status"] = "closed"
            issue["closed"] = datetime.now().isoformat()
            if comment:
                issue["closeComment"] = comment
            found = True
            break
    
    if not found:
        return {"success": False, "error": f"Issue #{issue_number} not found"}
    
    # Save issues
    with open(issues_file, "w") as f:
        json.dump(issues, f, indent=2)
    
    return {
        "success": True,
        "message": f"Closed issue #{issue_number}",
        "comment": comment
    }


def commit_with_issue(issue_number: int, message: str, files: list = None) -> dict:
    """Commit changes and reference issue."""
    # Stage files
    if files:
        for file in files:
            success, _ = run_git_command(["add", file])
            if not success:
                return {"success": False, "error": f"Failed to stage {file}"}
    else:
        run_git_command(["add", "-A"])
    
    # Commit with issue reference
    commit_msg = f"Issue #{issue_number}: {message}"
    success, output = run_git_command(["commit", "-m", commit_msg])
    
    if success:
        # Get commit hash
        _, hash_output = run_git_command(["rev-parse", "HEAD"])
        commit_hash = hash_output.strip()[:7]
        
        return {
            "success": True,
            "commit": commit_hash,
            "message": commit_msg,
            "issue": issue_number
        }
    else:
        return {"success": False, "error": output}


# =============================================================================
# MCP Tool Handlers
# =============================================================================

TOOLS = {
    "get_current_milestone": {
        "description": "Get the current thesis milestone based on today's date (Feb 8, 2026)",
        "parameters": {}
    },
    "list_milestones": {
        "description": "List all thesis milestones with deadlines and status",
        "parameters": {}
    },
    "list_issues": {
        "description": "List project issues with optional milestone filter",
        "parameters": {
            "milestone": {"type": "string", "description": "Filter by milestone ID"},
            "status": {"type": "string", "description": "Filter by status (open/closed)"}
        }
    },
    "create_issue": {
        "description": "Create a new issue for the thesis project",
        "parameters": {
            "title": {"type": "string", "required": True},
            "description": {"type": "string", "required": True},
            "milestone": {"type": "string"},
            "labels": {"type": "array"}
        }
    },
    "bulk_create_issues": {
        "description": "Create multiple issues at once from a list",
        "parameters": {
            "issues": {"type": "array", "required": True}
        }
    },
    "close_issue": {
        "description": "Close an issue with optional comment",
        "parameters": {
            "issue_number": {"type": "integer", "required": True},
            "comment": {"type": "string"}
        }
    },
    "commit_with_issue": {
        "description": "Commit changes with issue reference (e.g., 'Issue #5: Fix bug')",
        "parameters": {
            "issue_number": {"type": "integer", "required": True},
            "message": {"type": "string", "required": True},
            "files": {"type": "array"}
        }
    }
}


def handle_tool_call(tool_name: str, params: dict) -> dict:
    """Handle MCP tool call."""
    if tool_name == "get_current_milestone":
        return get_current_milestone()
    elif tool_name == "list_milestones":
        return list_milestones()
    elif tool_name == "list_issues":
        return list_issues(params.get("milestone"), params.get("status", "open"))
    elif tool_name == "create_issue":
        return create_issue(
            params["title"],
            params["description"],
            params.get("milestone"),
            params.get("labels")
        )
    elif tool_name == "bulk_create_issues":
        return bulk_create_issues(params["issues"])
    elif tool_name == "close_issue":
        return close_issue(params["issue_number"], params.get("comment"))
    elif tool_name == "commit_with_issue":
        return commit_with_issue(
            params["issue_number"],
            params["message"],
            params.get("files")
        )
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
            method = request.get("method")
            
            if method == "initialize":
                send_response({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "thesis-project-manager",
                        "version": "1.0.0"
                    }
                })
            
            elif method == "tools/list":
                send_response({"tools": TOOLS})
            
            elif method == "tools/call":
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
