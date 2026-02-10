# Thesis MCP Tools

Custom MCP (Model Context Protocol) servers for thesis project management.

## Servers

### 1. `thesis-project-manager`

Milestones, issues, and git operations.

| Tool | Description |
|------|-------------|
| `get_current_milestone` | Get current milestone based on today's date |
| `list_milestones` | List all 5 milestones with status and deadlines |
| `list_issues` | List issues (filter by milestone/status) |
| `create_issue` | Create a new issue |
| `bulk_create_issues` | Create multiple issues at once |
| `close_issue` | Close an issue with optional comment |
| `commit_with_issue` | Git commit referencing an issue number |

### 2. `thesis-code-quality`

Code analysis and testing.

| Tool | Description |
|------|-------------|
| `find_function` | Find where a function is defined |
| `list_functions_in_file` | List all functions/classes in a file |
| `find_dead_code` | Find potentially unused functions |
| `run_tests` | Run pytest on the project |
| `run_single_test` | Run a single test file or method |
| `check_for_errors` | Check syntax and import errors |

## Configuration

Configured in `~/.config/Code/User/mcp.json` using `stdio` transport with JSON-RPC 2.0.

## Issues Database

Issues are stored in `.mcp/issues.json`.
