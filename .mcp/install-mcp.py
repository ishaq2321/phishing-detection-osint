#!/usr/bin/env python3
import json

settings_path = "/home/ishaq2321/.config/Code/User/settings.json"

# Read current settings
with open(settings_path) as f:
    settings = json.load(f)

# Add MCP servers configuration
settings["chat.mcp.servers"] = {
    "thesis-project-manager": {
        "command": "python3",
        "args": ["/home/ishaq2321/Desktop/Thesis/.mcp/thesis-project-manager.py"],
        "env": {}
    },
    "thesis-code-quality": {
        "command": "python3",
        "args": ["/home/ishaq2321/Desktop/Thesis/.mcp/thesis-code-quality.py"],
        "env": {}
    }
}

# Write back
with open(settings_path, "w") as f:
    json.dump(settings, f, indent=4)

print("✅ MCP servers added to VS Code settings!")
print("📍 Location: ~/.config/Code/User/settings.json")
print("\n🔄 Please reload VS Code window to activate:")
print("   - Press Ctrl+Shift+P")
print("   - Type 'Reload Window'")
print("   - Press Enter")
