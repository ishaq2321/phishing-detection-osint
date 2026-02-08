# Thesis MCP Tools

Custom Model Context Protocol (MCP) servers for the BSc Thesis project.

## 🎯 Purpose

These tools help maintain context of:
- **Milestones & Deadlines** (Milestone 2 due Feb 20, 2026 - 12 days remaining!)
- **Issue Tracking** (create, close, bulk operations)
- **Code Quality** (find functions, check conventions, run tests)

## 📦 Servers

### 1. Thesis Project Manager (`thesis-project-manager.py`)

Tracks milestones, issues, and commits for thesis progress.

**Tools:**
- `get_current_milestone` - Get current milestone based on date (Feb 8, 2026)
- `list_milestones` - List all 5 thesis milestones with deadlines
- `list_issues` - List issues with optional milestone filter
- `create_issue` - Create new issue with milestone assignment
- `bulk_create_issues` - Create multiple issues from test audit/technical debt
- `close_issue` - Close issue with optional comment
- `commit_with_issue` - Commit with issue reference (e.g., "Issue #5: Fix bug")

**Example Usage:**
```python
# Get current milestone
{
  "id": "milestone-2",
  "title": "Milestone 2: Core Implementation",
  "deadline": "2026-02-20",
  "daysRemaining": 12,
  "deliverables": ["Core algorithm", "Backend integration", ...]
}

# Create issue
create_issue(
  title="Fix integration test failures",
  description="23/49 tests failing - need dict access fixes",
  milestone="milestone-2",
  labels=["testing", "bug"]
)

# Bulk create from audit
bulk_create_issues([
  {"title": "Fix OSINT mock configuration", "milestone": "milestone-2"},
  {"title": "Adjust ML risk score expectations", "milestone": "milestone-2"},
  ...
])
```

### 2. Thesis Code Quality (`thesis-code-quality.py`)

Analyzes code for errors, gaps, conventions, and test coverage.

**Tools:**
- `find_function` - Find function definition (file, line, args)
- `list_functions_in_file` - List all functions/classes in a file
- `check_naming_conventions` - Verify camelCase/snake_case rules
- `find_dead_code` - Find unused functions and imports
- `run_tests` - Run pytest with optional coverage
- `check_test_coverage` - Coverage analysis for specific file
- `check_for_errors` - Run flake8 and mypy linting
- `validate_thesis_conventions` - Full validation (naming, dead code, tests)

**Example Usage:**
```python
# Find function definition
find_function("extractFeatures", "backend/ml")
# Returns: {"file": "backend/ml/featureExtractor.py", "line": 145, ...}

# Check conventions
validate_thesis_conventions()
# Returns: {"status": "pass/fail", "issues": [...]}

# Run tests with coverage
run_tests("tests/integration/", coverage=True)
# Returns: {"passed": 36, "failed": 13, ...}
```

## 🚀 Setup (for VS Code)

Add to your MCP settings (`.vscode/mcp-settings.json` or User Settings):

```json
{
  "mcpServers": {
    "thesis-project": {
      "command": "python3",
      "args": ["/home/ishaq2321/Desktop/Thesis/.mcp/thesis-project-manager.py"]
    },
    "thesis-quality": {
      "command": "python3",
      "args": ["/home/ishaq2321/Desktop/Thesis/.mcp/thesis-code-quality.py"]
    }
  }
}
```

## 📊 Milestone Tracking

**Current Status (Feb 8, 2026):**
- ✅ Milestone 1: Complete (Dec 20, 2025)
- 🔄 **Milestone 2: IN PROGRESS (12 days remaining!)**
  - Core algorithm: ✅ Done
  - Backend integration: ✅ Done
  - Tests: 🔄 473/473 unit (100%), 36/49 integration (73%)
  - Dataset: ⏳ Pending
- ⏳ Milestone 3: Upcoming (Mar 25, 2026)
- ⏳ Milestone 4: Upcoming (Apr 15, 2026)
- 🎓 Final Submission: May 1, 2026

## 📋 Issue Tracking

Issues are stored in `.mcp/issues.json` and tracked with:
- Issue number (auto-incremented)
- Title, description, milestone
- Labels (bug, feature, testing, etc.)
- Status (open/closed)
- Creation/close timestamps

**Naming Convention:**
- Commits: `"Issue #N: description"`
- Example: `"Issue #12: Fix dict subscriptable errors"`

## 🔍 Code Quality Standards

From `copilot-instructions.md`:
- **Naming:** camelCase for code, snake_case for database
- **No Dead Code:** Remove unused functions/imports
- **No Empty Files:** Every file has purpose
- **Testing:** Comprehensive unit + integration tests
- **Documentation:** Clear comments and docstrings

## 🎓 Thesis Context

- **Project:** Phishing Detection Using OSINT-Enhanced Features
- **Student:** Ishaq Muhammad (PXPRGK)
- **Supervisor:** Arafat
- **Institution:** ELTE Faculty of Informatics
- **Deadline:** May 1, 2026 (83 days remaining)

## 📝 Notes

- MCP tools provide context awareness for Copilot
- Helps track progress across multiple sessions
- Maintains thesis milestone visibility
- Enforces code quality standards
- Simplifies issue management workflow
