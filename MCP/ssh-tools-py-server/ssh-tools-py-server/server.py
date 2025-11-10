import asyncio
import io
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import paramiko

# ========= Utilities: JSON-RPC over stdio (minimal MCP subset) =========

SERVER_INFO = {"name": "ssh-tools-py-server", "version": "1.0.1"}
PROTOCOL_VERSION = "2024-11-05"

def jsonrpc_response(id_: Any, result: Any = None, error: Dict[str, Any] = None) -> Dict[str, Any]:
    msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    return msg

def write_json(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()

# ========= SSH and Command Helpers =========

def _is_read_only_command(cmd: str) -> bool:
    c = cmd.strip()
    readonly_patterns = [
        r"^ls(\s|$)",
        r"^(cat|grep|egrep|fgrep)(\s|$)",
        r"^ps(\s|$)",
        r"^whoami(\s|$)",
        r"^uptime(\s|$)",
        r"^df(\s|$)",
        r"^free(\s|$)",
        r"^id(\s|$)",
        r"^echo(\s|$)",
        r"^head(\s|$)",
        r"^tail(\s|$)",
        r"^hostname(\s|$)",
        r"^uname(\s|$)",
        r"^findmnt(\s|$)",
        r"^blkid(\s|$)",
        r"^lsblk(\s|$)",
        r"^vgs(\s|$)",
        r"^lvs(\s|$)",
        r"^vgdisplay(\s|$)",
        r"^lvdisplay(\s|$)",
    ]
    return any(re.compile(p, re.IGNORECASE).match(c) for p in readonly_patterns)

def _load_pkey_pem(private_key_pem: str) -> Optional[paramiko.PKey]:
    buf = io.StringIO(private_key_pem)
    for key_cls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key, paramiko.DSSKey):
        buf.seek(0)
        try:
            return key_cls.from_private_key(buf)
        except Exception:
            continue
    return None

def _sh_single_quote(s: str) -> str:
    # POSIX-safe single-quote encoding: end quote, insert escaped single quote, reopen
    # Turns: abc'def -> 'abc'"'"'def'
    return "'" + s.replace("'", "'\"'\"'") + "'"

def _wrap_bash(command: str, working_directory: Optional[str] = None, use_sudo: bool = False) -> str:
    # Build the command and wrap it for bash -lc with safe single-quoting
    cmd = command
    if working_directory:
        cmd = f"cd {_sh_single_quote(working_directory)} && {cmd}"
    wrapped = f"bash -lc {_sh_single_quote(cmd)}"
    if use_sudo:
        wrapped = f"sudo -n {wrapped}"
    return wrapped

def _ssh_exec(
    host: str,
    username: str,
    port: int = 22,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    command: Optional[str] = None,
    script: Optional[str] = None,
    working_directory: Optional[str] = None,
    use_sudo: bool = False,
    timeout_sec: Optional[int] = None,
) -> Tuple[str, str, int]:
    if not command and not script:
        raise ValueError("Provide either command or script")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    pkey = _load_pkey_pem(private_key) if private_key else None

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            allow_agent=False,
            look_for_keys=False,
            timeout=timeout_sec or 20,
            banner_timeout=timeout_sec or 20,
            auth_timeout=timeout_sec or 20,
        )

        if script:
            # Upload script to /tmp and execute
            sftp = client.open_sftp()
            remote_path = f"/tmp/mcp_script_{int(time.time())}_{os.getpid()}.sh"
            with sftp.file(remote_path, "w") as f:
                f.write(script)
            sftp.chmod(remote_path, 0o700)
            sftp.close()

            base_cmd = f"/bin/bash -euo pipefail {remote_path}; rc=$?; rm -f {remote_path}; exit $rc"
            exec_cmd = _wrap_bash(base_cmd, working_directory=working_directory, use_sudo=use_sudo)
        else:
            assert command is not None
            exec_cmd = _wrap_bash(command, working_directory=working_directory, use_sudo=use_sudo)

        stdin, stdout, stderr = client.exec_command(exec_cmd, get_pty=False, timeout=timeout_sec or 60)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        return out, err, rc
    except Exception as e:
        return "", f"SSH error: {e}", 255
    finally:
        try:
            client.close()
        except Exception:
            pass

# ========= Planning and Facts =========

def _parse_os_facts(os_release: str, mgrs: str) -> Dict[str, Any]:
    facts: Dict[str, Any] = {}
    kv: Dict[str, str] = {}
    for ln in os_release.splitlines():
        m = re.match(r"^([A-Z0-9_]+)=(.*)$", ln)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if val and ((val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'"))):
            val = val[1:-1]
        kv[key] = val
    facts["osId"] = kv.get("ID", "").lower() or None
    facts["osVersionId"] = kv.get("VERSION_ID") or None
    if facts["osVersionId"]:
        try:
            facts["osMajor"] = int(str(facts["osVersionId"]).split(".")[0])
        except Exception:
            facts["osMajor"] = None
    else:
        facts["osMajor"] = None

    t = mgrs or ""
    facts["hasDnf"] = ("HAS_DNF=1" in t) or bool(re.search(r"(?:^|\s)dnf(?:\s|$)|/dnf\b", t))
    facts["hasYum"] = ("HAS_YUM=1" in t) or bool(re.search(r"(?:^|\s)yum(?:\s|$)|/yum\b", t))
    facts["hasSystemctl"] = ("HAS_SYSTEMCTL=1" in t) or ("systemctl" in t)
    return facts

def _pick_pkg_mgr(facts: Optional[Dict[str, Any]]) -> Optional[str]:
    if not facts:
        return None
    if facts.get("osMajor") and int(facts["osMajor"]) >= 8 and facts.get("hasDnf"):
        return "dnf"
    if facts.get("hasDnf") and not facts.get("hasYum"):
        return "dnf"
    if facts.get("hasYum"):
        return "yum"
    return None

def _pick_svc_mgr(facts: Optional[Dict[str, Any]]) -> Optional[str]:
    if not facts:
        return None
    return "systemctl" if facts.get("hasSystemctl") else "service"

def _probe_facts(
    host: str,
    username: str,
    port: int = 22,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    timeout_sec: Optional[int] = None,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    osr_out, _, _ = _ssh_exec(
        host, username, port, password, private_key, command="cat /etc/os-release || true", timeout_sec=timeout_sec
    )
    mgrs_cmd = "sh -lc '([ -x \"$(command -v dnf)\" ] && echo HAS_DNF=1 && command -v dnf) || echo HAS_DNF=0; " \
               "([ -x \"$(command -v yum)\" ] && echo HAS_YUM=1 && command -v yum) || echo HAS_YUM=0; " \
               "([ -x \"$(command -v systemctl)\" ] && echo HAS_SYSTEMCTL=1 && command -v systemctl) || echo HAS_SYSTEMCTL=0'"
    mgrs_out, _, _ = _ssh_exec(
        host, username, port, password, private_key, command=mgrs_cmd, timeout_sec=timeout_sec
    )
    facts = _parse_os_facts(osr_out, mgrs_out)
    return facts, {"osRelease": osr_out, "mgrs": mgrs_out}

def _plan_commands(instruction: str, facts: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    pkg_mgr = _pick_pkg_mgr(facts)
    svc_mgr = _pick_svc_mgr(facts)

    prechecks = [
        {"id": "pre-os-release", "description": "Display OS release info", "command": "cat /etc/os-release || true", "useSudo": False, "readOnly": True},
        {"id": "pre-managers", "description": "Check package/service manager availability", "command": "command -v dnf || true; command -v yum || true; command -v systemctl || true; command -v service || true", "useSudo": False, "readOnly": True},
    ]
    postchecks: List[Dict[str, Any]] = []
    steps: List[Dict[str, Any]] = []
    assumptions: List[str] = []
    lower = instruction.lower().strip()

    def extract(pattern: str) -> Optional[List[str]]:
        m = re.search(pattern, lower, flags=re.IGNORECASE)
        if not m:
            return None
        captured = (m.group(1) or "").strip()
        parts = [p.strip() for p in re.split(r"[,\s]+", captured) if p.strip()]
        return parts or None

    raw_cmd = None
    m1 = re.search(r"(?:^|\b)run:\s*(.+)$", instruction, flags=re.IGNORECASE)
    m2 = re.search(r"(?:^|\b)command:\s*(.+)$", instruction, flags=re.IGNORECASE)
    if m1:
        raw_cmd = m1.group(1).strip()
    elif m2:
        raw_cmd = m2.group(1).strip()

    install_t = extract(r"\binstall\s+(.+)$")
    remove_t = extract(r"\b(?:remove|uninstall)\s+(.+)$")
    start_t = extract(r"\bstart\s+(?:the\s+)?(.+?)(?:\s+service)?$")
    stop_t = extract(r"\bstop\s+(?:the\s+)?(.+?)(?:\s+service)?$")
    restart_t = extract(r"\brestart\s+(?:the\s+)?(.+?)(?:\s+service)?$")
    enable_t = extract(r"\benable\s+(?:the\s+)?(.+?)(?:\s+service)?$")
    disable_t = extract(r"\bdisable\s+(?:the\s+)?(.+?)(?:\s+service)?$")
    status_t = extract(r"\bstatus\s+(?:the\s+)?(.+?)(?:\s+service)?$")

    if not pkg_mgr:
        assumptions.append("Package manager not confirmed; will prefer dnf on OL8+ and yum otherwise.")
    if not svc_mgr:
        assumptions.append("Service manager not confirmed; will prefer systemctl and fallback to service/chkconfig.")

    def push_pkg(op: str, names: List[str]):
        if not names:
            return
        mgr = pkg_mgr or "dnf"
        pkg_list = " ".join(names)
        cmd = f"{mgr} -y {op} {pkg_list}"
        steps.append({
            "id": f"pkg-{op}-{mgr}",
            "description": f"{op} packages via {mgr}: {pkg_list}",
            "command": cmd,
            "useSudo": True,
            "readOnly": False,
            "expectedOutcome": f"Packages {op}ed",
        })
        if op == "install":
            for i, n in enumerate(names):
                postchecks.append({
                    "id": f"post-rpmq-{n}-{i}",
                    "description": f"Verify package installed: {n}",
                    "command": f"rpm -q {n}",
                    "useSudo": False,
                    "readOnly": True,
                    "expectedOutcome": f"rpm -q prints NVRA for {n}",
                })

    def svc_name(s: str) -> str:
        return re.sub(r"\.(service|unit)$", "", s, flags=re.IGNORECASE)

    def push_svc(action: str, names: List[str]):
        if not names:
            return
        for idx, raw in enumerate(names):
            svc = svc_name(raw)
            if svc_mgr == "systemctl":
                steps.append({
                    "id": f"svc-{action}-systemctl-{svc}-{idx}",
                    "description": f"{action} service via systemctl: {svc}",
                    "command": f"systemctl {action} {svc}",
                    "useSudo": True if action in ["start","stop","restart","enable","disable"] else False,
                    "readOnly": action == "status",
                    "expectedOutcome": f"systemctl {action} {svc} succeeds",
                })
            else:
                if action in ["enable","disable"]:
                    onoff = "on" if action == "enable" else "off"
                    steps.append({
                        "id": f"svc-{action}-chkconfig-{svc}-{idx}",
                        "description": f"{action} service via chkconfig: {svc}",
                        "command": f"chkconfig {svc} {onoff}",
                        "useSudo": True,
                        "readOnly": False,
                    })
                elif action == "status":
                    steps.append({
                        "id": f"svc-status-service-{svc}-{idx}",
                        "description": f"status via service: {svc}",
                        "command": f"service {svc} status",
                        "useSudo": False,
                        "readOnly": True,
                    })
                else:
                    steps.append({
                        "id": f"svc-{action}-service-{svc}-{idx}",
                        "description": f"{action} via service: {svc}",
                        "command": f"service {svc} {action}",
                        "useSudo": True,
                        "readOnly": False,
                    })
            if action in ["start","restart"]:
                if svc_mgr == "systemctl":
                    postchecks.append({
                        "id": f"post-is-active-{svc}-{idx}",
                        "description": f"Verify active: {svc}",
                        "command": f"systemctl is-active {svc}",
                        "useSudo": False,
                        "readOnly": True,
                    })
                else:
                    postchecks.append({
                        "id": f"post-status-service-{svc}-{idx}",
                        "description": f"Verify status via service: {svc}",
                        "command": f"service {svc} status",
                        "useSudo": False,
                        "ReadOnly": True if True else True,  # keep schema similar
                    })
            if action == "enable" and svc_mgr == "systemctl":
                postchecks.append({
                    "id": f"post-is-enabled-{svc}-{idx}",
                    "description": f"Verify enabled: {svc}",
                    "command": f"systemctl is-enabled {svc}",
                    "useSudo": False,
                    "readOnly": True,
                })

    if install_t: push_pkg("install", install_t)
    if remove_t: push_pkg("remove", remove_t)
    if start_t: push_svc("start", start_t)
    if stop_t: push_svc("stop", stop_t)
    if restart_t: push_svc("restart", restart_t)
    if enable_t: push_svc("enable", enable_t)
    if disable_t: push_svc("disable", disable_t)
    if status_t: push_svc("status", status_t)

    if raw_cmd:
        steps.append({
            "id": "explicit-command",
            "description": "Run explicit command from instruction",
            "command": raw_cmd,
            "useSudo": False,
            "readOnly": False,
        })

    if not steps:
        steps.append({
            "id": "fallback-command",
            "description": "Run instruction text as a shell command",
            "command": instruction.strip(),
            "useSudo": False,
            "readOnly": False,
        })

    return {
        "summary": f"Plan for: {instruction.strip()}",
        "pkgManager": pkg_mgr,
        "serviceManager": svc_mgr,
        "prechecks": prechecks,
        "steps": steps,
        "postchecks": postchecks,
        "assumptions": assumptions or None,
    }

def _build_remediation_plan(attempted_command: Optional[str], stdout: str, stderr: str, exit_code: Optional[int], facts: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    def mgr() -> str:
        if not facts:
            return "dnf"
        if facts.get("osMajor") and int(facts["osMajor"]) >= 8 and facts.get("hasDnf"):
            return "dnf"
        if facts.get("hasDnf") and not facts.get("hasYum"):
            return "dnf"
        return "yum"

    def svc_mgr() -> str:
        if not facts:
            return "systemctl"
        return "systemctl" if facts.get("hasSystemctl") else "service"

    steps: List[Dict[str, Any]] = []
    prechecks: List[Dict[str, Any]] = [
        {"id":"diag-os-release","description":"Show /etc/os-release","command":"cat /etc/os-release || true","useSudo":False,"readOnly":True},
        {"id":"diag-mgrs","description":"Check managers (dnf/yum/systemctl/service)","command":"command -v dnf || true; command -v yum || true; command -v systemctl || true; command -v service || true","useSudo":False,"readOnly":True},
    ]
    postchecks: List[Dict[str, Any]] = []
    assumptions: List[str] = []

    def retry(with_sudo: bool) -> Optional[Dict[str, Any]]:
        if not attempted_command:
            return None
        return {"id": f"retry-{'sudo' if with_sudo else 'nosudo'}", "description": f"Retry original command {'with sudo' if with_sudo else 'without sudo'}", "command": attempted_command, "useSudo": with_sudo, "readOnly": False}

    # Heuristics
    if re.search(r"sudo: command not found", stderr or "", flags=re.IGNORECASE):
        steps.append({"id": f"fix-sudo-install-{mgr()}", "description": "Install sudo", "command": f"{mgr()} -y install sudo", "useSudo": True, "readOnly": False, "expectedOutcome":"sudo installed"})
        r = retry(True)
        if r: steps.append(r)

    if (stderr and re.search(r"permission denied", stderr, re.IGNORECASE)) or (exit_code == 13):
        r = retry(True)
        if r: steps.append(r)

    if (stderr and "dnf: command not found" in stderr) or (stdout and "dnf: command not found" in stdout):
        assumptions.append("dnf missing; try yum instead")
        r = retry(False)
        if r: steps.append(r)

    if stderr and "systemctl: command not found" in stderr:
        assumptions.append("systemctl missing; use service/chkconfig")
        steps.append({"id": "hint-service", "description":"Use service/chkconfig instead of systemctl", "command":"echo 'Use service <name> start|stop|status and chkconfig for enable/disable'", "useSudo": False, "readOnly": True})

    if stderr and (re.search(r"Unit .* not found", stderr) or "could not be found" in stderr):
        steps.append({"id":"svc-list-hint", "description":"List services to find correct name", "command":"systemctl list-unit-files | grep -i service || service --status-all 2>/dev/null || true", "useSudo": False, "readOnly": True})

    repo_err = any(
        re.search(p, stderr or "", re.IGNORECASE)
        for p in [r"No package .* available", r"Failed to download metadata", r"repomd\.xml", r"Cannot find a valid baseurl", r"cannot find name for group"]
    )
    if repo_err:
        steps.append({"id": f"fix-repos-clean-{mgr()}", "description":"Clean caches", "command": f"{mgr()} clean all", "useSudo": True, "readOnly": False})
        steps.append({"id": f"fix-repos-makecache-{mgr()}", "description":"Refresh repo metadata", "command": f"{mgr()} makecache", "useSudo": True, "ReadOnly": False if False else False})
        if mgr() == "dnf":
            steps.append({"id":"dnf-plugins-core","description":"Ensure dnf-plugins-core for config-manager","command":"dnf -y install dnf-plugins-core","useSudo": True,"readOnly": False})
            steps.append({"id":"enable-appstream","description":"Enable AppStream (OL8)","command":"dnf config-manager --set-enabled ol8_appstream || true","useSudo": True,"readOnly": False})
            steps.append({"id":"enable-baseos","description":"Enable BaseOS (OL8)","command":"dnf config-manager --set-enabled ol8_baseos_latest || true","useSudo": True,"readOnly": False})
        else:
            steps.append({"id":"yum-utils","description":"Ensure yum-utils for yum-config-manager","command":"yum -y install yum-utils","useSudo": True,"readOnly": False})
            steps.append({"id":"enable-ol7-latest","description":"Enable ol7_latest","command":"yum-config-manager --enable ol7_latest || true","useSudo": True,"readOnly": False})

    if re.search(r"Temporary failure in name resolution|Name or service not known|Could not resolve host", stderr or "", re.IGNORECASE):
        assumptions.append("DNS/network issue")
        steps.extend([
            {"id":"net-dns","description":"Show resolv.conf","command":"cat /etc/resolv.conf || true","useSudo": False,"readOnly": True},
            {"id":"net-route","description":"Show default route","command":"ip route || route -n || true","useSudo": False,"readOnly": True},
            {"id":"net-http","description":"Check HTTP to repo","command":"curl -s -o /dev/null -w '%{http_code}\\n' http://repo.oracle.com/ || true","useSudo": False,"readOnly": True},
        ])

    if re.search(r"SELinux is preventing|avc: denied|audit\(", stderr or "", re.IGNORECASE):
        assumptions.append("Potential SELinux denial")
        steps.append({"id":"selinux-audit","description":"Show recent SELinux denials","command":"ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | tail -n 50 || true","useSudo": True,"readOnly": True})

    if not steps:
        steps.append({"id":"diag-logs","description":"Show recent logs","command":"journalctl -n 100 --no-pager 2>/dev/null || dmesg | tail -n 100 || true","useSudo": True,"readOnly": True})

    return {
        "summary": "Remediation plan based on error output",
        "pkgManager": mgr(),
        "serviceManager": svc_mgr(),
        "prechecks": prechecks,
        "steps": steps,
        "postchecks": postchecks,
        "assumptions": assumptions or None,
    }

# ========= Tool Implementations =========

def _tool_ssh_probe_os(arguments: Dict[str, Any]) -> Dict[str, Any]:
    host = arguments["host"]
    username = arguments["username"]
    port = int(arguments.get("port", 22))
    password = arguments.get("password")
    private_key = arguments.get("privateKey")
    timeout = arguments.get("timeoutSec")
    facts, raw = _probe_facts(host, username, port, password, private_key, timeout)
    return {"content": [{"type": "text", "text": json.dumps({"facts": facts, "raw": raw}, indent=2)}], "data": {"facts": facts, "raw": raw}}

def _tool_ssh_propose_commands(arguments: Dict[str, Any]) -> Dict[str, Any]:
    host = arguments["host"]
    username = arguments["username"]
    port = int(arguments.get("port", 22))
    password = arguments.get("password")
    private_key = arguments.get("privateKey")
    instruction = arguments["instruction"]
    timeout = arguments.get("timeoutSec")
    facts, _ = _probe_facts(host, username, port, password, private_key, timeout)
    plan = _plan_commands(instruction, facts)
    return {"content": [{"type": "text", "text": json.dumps({"plan": plan, "facts": facts}, indent=2)}], "data": {"plan": plan, "facts": facts}}

def _tool_ssh_execute(arguments: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    host = arguments["host"]
    username = arguments["username"]
    port = int(arguments.get("port", 22))
    password = arguments.get("password")
    private_key = arguments.get("privateKey")
    working_directory = arguments.get("workingDirectory")
    timeout = arguments.get("timeoutSec")

    command: Optional[str] = arguments.get("command")
    script: Optional[str] = arguments.get("script")
    steps = arguments.get("steps")
    if steps and isinstance(steps, list) and len(steps) > 0:
        lines = ["set -euo pipefail"]
        for s in steps:
            c = s.get("command")
            if not isinstance(c, str) or not c.strip():
                return {"content": [{"type": "text", "text": "Invalid step: missing command"}], "isError": True}
            if s.get("useSudo", False):
                lines.append(f"sudo -n {c}")
            else:
                lines.append(c)
        script = "\n".join(lines)
        command = None

    if not command and not script:
        return {"content": [{"type": "text", "text": "Provide one of: steps, script, or command"}], "isError": True}

    approved = bool(arguments.get("approved", False) or meta.get("approved", False))
    mutating = bool(script) or (bool(command) and not _is_read_only_command(command or ""))
    if mutating and not approved:
        msg = f"Approval required for mutating operation. Refusing to run.\nSet approved=true or _meta.approved=true to proceed.\nCommand: {command or '[script]'}"
        return {"content": [{"type": "text", "text": msg}], "requires_approval": True, "isError": False}

    use_sudo = bool(arguments.get("useSudo", False)) and not steps
    out, err, rc = _ssh_exec(
        host=host,
        username=username,
        port=port,
        password=password,
        private_key=private_key,
        command=command,
        script=script,
        working_directory=working_directory,
        use_sudo=use_sudo,
        timeout_sec=timeout,
    )
    return {"content": [{"type": "text", "text": json.dumps({"exitCode": rc, "stdout": out, "stderr": err}, indent=2)}], "data": {"exitCode": rc, "stdout": out, "stderr": err}}

def _tool_ssh_remediate(arguments: Dict[str, Any]) -> Dict[str, Any]:
    attempt = arguments.get("attemptedCommand")
    stdout = arguments.get("stdout") or ""
    stderr = arguments.get("stderr") or ""
    exit_code = arguments.get("exitCode")
    facts = arguments.get("facts")
    plan = _build_remediation_plan(attempt, stdout, stderr, exit_code, facts)
    return {"content": [{"type": "text", "text": json.dumps({"plan": plan}, indent=2)}], "data": {"plan": plan}}

TOOLS = [
    {
        "name": "ssh_probe_os",
        "description": "Probe remote host (Oracle Linux 7/8) for OS facts and available managers (dnf/yum/systemctl).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "number", "default": 22},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "privateKey": {"type": "string"},
                "timeoutSec": {"type": "number"},
            },
            "required": ["host", "username"],
        },
    },
    {
        "name": "ssh_propose_commands",
        "description": "Given an instruction, generate a safe, ordered plan of commands tailored for Oracle Linux 7/8. No execution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "number", "default": 22},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "privateKey": {"type": "string"},
                "instruction": {"type": "string"},
                "timeoutSec": {"type": "number"},
            },
            "required": ["host", "username", "instruction"],
        },
    },
    {
        "name": "ssh_execute",
        "description": "Execute a command/script/plan on the remote host via SSH. Mutating ops require explicit approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "number", "default": 22},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "privateKey": {"type": "string"},
                "command": {"type": "string"},
                "script": {"type": "string"},
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"command": {"type": "string"}, "useSudo": {"type": "boolean"}},
                        "required": ["command"],
                    },
                },
                "workingDirectory": {"type": "string"},
                "useSudo": {"type": "boolean"},
                "timeoutSec": {"type": "number"},
                "approved": {"type": "boolean"},
            },
            "required": ["host", "username"],
        },
    },
    {
        "name": "ssh_remediate",
        "description": "Given a failed command's stdout/stderr/exitCode and optional OS facts, propose remediation steps. No execution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "attemptedCommand": {"type": "string"},
                "stdout": {"type": "string"},
                "stderr": {"type": "string"},
                "exitCode": {"type": "number"},
                "facts": {
                    "type": "object",
                    "properties": {
                        "osId": {"type": "string"},
                        "osVersionId": {"type": "string"},
                        "osMajor": {"type": "number"},
                        "hasDnf": {"type": "boolean"},
                        "hasYum": {"type": "boolean"},
                        "hasSystemctl": {"type": "boolean"},
                    },
                },
            },
            "required": [],
        },
    },
]

def handle_initialize(req: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "serverInfo": SERVER_INFO,
        "capabilities": {"tools": {}},
    }

def handle_tools_list(req: Dict[str, Any]) -> Dict[str, Any]:
    return {"tools": TOOLS}

def handle_tools_call(req: Dict[str, Any]) -> Dict[str, Any]:
    params = req.get("params") or {}
    name = params.get("name")
    arguments = params.get("arguments") or {}
    meta = params.get("_meta") or {}

    if name == "ssh_probe_os":
        return _tool_ssh_probe_os(arguments)
    if name == "ssh_propose_commands":
        return _tool_ssh_propose_commands(arguments)
    if name == "ssh_execute":
        return _tool_ssh_execute(arguments, meta)
    if name == "ssh_remediate":
        return _tool_ssh_remediate(arguments)

    return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}

# ========= Main loop =========

def main() -> None:
    # Read newline-delimited JSON requests from stdin
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            # Ignore malformed
            continue

        method = req.get("method")
        id_ = req.get("id")

        # Notification (no id) - ignore unless special
        if method == "notifications/initialized":
            # no-op
            continue

        try:
            if method == "initialize":
                result = handle_initialize(req)
                write_json(jsonrpc_response(id_, result=result))
            elif method == "tools/list":
                result = handle_tools_list(req)
                write_json(jsonrpc_response(id_, result=result))
            elif method == "tools/call":
                result = handle_tools_call(req)
                write_json(jsonrpc_response(id_, result=result))
            else:
                write_json(jsonrpc_response(id_, error={"code": -32601, "message": f"Method not found: {method}"}))
        except Exception as e:
            write_json(jsonrpc_response(id_, error={"code": -32000, "message": f"Server error: {e}"}))

if __name__ == "__main__":
    main()
