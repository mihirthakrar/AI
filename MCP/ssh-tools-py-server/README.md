# SSH Tools MCP Server (Python, stdio)

A minimal Model Context Protocol (MCP) server that executes commands on remote Linux hosts over SSH. It exposes safe, support-oriented tools for probing OS facts, proposing remediation plans, executing approved scripts/commands, and analyzing failures.

- Transport: stdio (designed to run inside Docker and connect to clients like VS Code + Cline)
- Language/Runtime: Python
- Location: `ssh-tools-py-server/` (this folder)

## Tools exposed

- `ssh_probe_os`
  - Purpose: Probe remote host for OS facts and available managers (dnf/yum/systemctl).
  - Inputs: `host`, `port?`, `username`, `password?`, `privateKey?`, `timeoutSec?`.
  - Output: JSON with detected OS info and manager availability.

- `ssh_propose_commands`
  - Purpose: Given a natural-language instruction, generate a safe plan of commands (Oracle Linux 7/8 oriented). No execution.
  - Inputs: `host`, `port?`, `username`, `password?`, `privateKey?`, `instruction`, `timeoutSec?`.
  - Output: Ordered, annotated command plan (read-only).

- `ssh_execute`
  - Purpose: Execute a command, a multi-line script, or an array of steps on the remote host.
  - Inputs:
    - `host`, `port?`, `username`, `password?`, `privateKey?`
    - `command?` (string), `script?` (string), or `steps?` (array of `{ command, useSudo? }`)
    - `workingDirectory?`, `useSudo?`, `timeoutSec?`, `approved?`
  - Output: Exit code, stdout, stderr.
  - Approval: Mutating operations require explicit approval (`approved: true`).

- `ssh_remediate`
  - Purpose: Given a failed command’s stdout/stderr/exitCode (and optional OS facts), propose remediation steps. No execution.
  - Inputs: `attemptedCommand`, `stdout`, `stderr`, `exitCode`, `facts?`.
  - Output: Safe, ordered remediation plan.

Notes:
- “Mutating operations” include service restarts, installs, config changes, file writes/deletes, firewall/SELinux changes, etc.
- Read-only operations (e.g., `df -h`, `ps`, `journalctl` viewing) typically do NOT require approval.

## Requirements

- Docker installed (Windows 11 supported)
- A client that can talk MCP over stdio (e.g., VS Code + Cline)
- Remote host access via SSH (username/password or private key)

## Build (Docker)

From the repository root or this folder:

```powershell
# Build the image
docker build -t mcp-ssh-tools-py:latest .\ssh-tools-py-server
```

## Run (standalone test)

```powershell
docker run --rm -i mcp-ssh-tools-py:latest
```

The server will wait on stdio for MCP JSON-RPC messages. In normal use, your MCP client (e.g., Cline) manages the process.

## VS Code + Cline configuration

Add an entry in your VS Code settings for the MCP server. Example workspace settings (`.vscode/settings.json`) or user settings:

```json
{
  "cline.mcpServers": {
    "ssh-tools-py": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "mcp-ssh-tools-py:latest"]
    }
  }
}
```

If you also use Claude Dev (same engine), optionally mirror the config:

```json
{
  "claudeDev.mcpServers": {
    "ssh-tools-py": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "mcp-ssh-tools-py:latest"]
    }
  }
}
```

Restart the client session; you should see “ssh-tools-py” listed under connected MCP servers.

## Usage patterns and examples

Your MCP client UI will guide the invocation. The following examples illustrate typical tool payloads (conceptual):

### 1) Probe OS (read-only)

```json
{
  "server": "ssh-tools-py",
  "tool": "ssh_probe_os",
  "args": {
    "host": "10.0.0.10",
    "username": "oracle",
    "password": "********",
    "timeoutSec": 30
  }
}
```

Expected: OS ID/version, manager availability (dnf/yum/systemctl), useful for tailoring later commands.

### 2) Execute read-only checks

```json
{
  "server": "ssh-tools-py",
  "tool": "ssh_execute",
  "args": {
    "host": "10.0.0.10",
    "username": "oracle",
    "password": "********",
    "script": "#!/bin/bash\nset -e\nhostname; date\ndf -h\nss -ltnp | head -n 20\n",
    "timeoutSec": 120
  }
}
```

No `approved` required because this is read-only.

### 3) GoldenGate health (classic, as oracle)

If GoldenGate lives at `/home/oracle/gg_home`, you can query:

```json
{
  "server": "ssh-tools-py",
  "tool": "ssh_execute",
  "args": {
    "host": "10.0.0.10",
    "username": "root",
    "password": "********",
    "script": "#!/bin/bash\nset -e\nsu - oracle -c \"printf 'info all\\nexit\\n' | /home/oracle/gg_home/ggsci\"\n",
    "timeoutSec": 90
  }
}
```

Note: Requires `su` from root to oracle (or log in directly as oracle). If `ggsci` is elsewhere, adjust the path.

### 4) Mutating operations (approval required)

For actions like restarting services:

```json
{
  "server": "ssh-tools-py",
  "tool": "ssh_execute",
  "args": {
    "host": "10.0.0.10",
    "username": "root",
    "password": "********",
    "steps": [
      { "command": "systemctl restart sshd", "useSudo": false }
    ],
    "timeoutSec": 60,
    "approved": true
  }
}
```

If `approved` is omitted, the server will refuse to run mutating operations.

## Safety and approvals

- Read-only first: Default to diagnostics (e.g., `df -h`, `ps`, `journalctl`).
- “Requires confirmation” examples:
  - Restarting services, editing configs, firewall/SELinux changes
  - Installing/removing packages and drivers
  - Database operations (shutdown/startup), GoldenGate start/stop
- Use `approved: true` for any mutating plan/command.
- Prefer key-based SSH where possible; never commit secrets to source control.

## Troubleshooting

- Connection errors: Verify network path (port 22), credentials, and `sshd` on the target host.
- Permission denied: Confirm the provided user has the necessary privileges. For `su - oracle`, the session user must be root or have correct PAM/sudo policy.
- Timeouts: Increase `timeoutSec`, or split long procedures into smaller steps and poll.
- Pathing: If `sqlplus` or `ggsci` is “not found”, ensure `ORACLE_HOME/bin` or the GG home path is set. Use `oraenv` plus `ORACLE_SID` within the script.

## Development notes

- Server entry point: `server.py`
- Dockerfile: `ssh-tools-py-server/Dockerfile`
- The image installs:
  - `mcp` (Python SDK for Model Context Protocol)
  - `paramiko` for SSH
- Default command (in container):
  - `CMD ["python", "/app/server.py"]`

## License / Contributions

This example MCP server is provided for internal support workflows. Review and adapt to your environment’s policies before use on production systems. Contributions should include tests and adhere to safe-by-default execution patterns.
