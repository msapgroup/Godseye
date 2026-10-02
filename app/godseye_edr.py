"""Optional GODSEYE EDR rule packs and endpoint policy storage.

Rule text is stored in SQLite so full appliance backups include the approved
rules. A rule must be validated by the server's YARA-X CLI before publication.
"""
import hashlib
import os
import re
import subprocess
import tempfile

MAX_RULE_BYTES = 1024 * 1024


def ensure_schema(c):
    c.execute("""CREATE TABLE IF NOT EXISTS edr_policies (
        agent_id INTEGER PRIMARY KEY REFERENCES windows_agents(id) ON DELETE CASCADE,
        enabled INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS edr_rule_packs (
        version INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL,
        sha256 TEXT NOT NULL, rules TEXT NOT NULL, created_at TEXT NOT NULL,
        created_by TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0)""")


def validate_rule_text(rules):
    raw = rules.encode("utf-8")
    if not raw or len(raw) > MAX_RULE_BYTES:
        raise ValueError("Rule file must contain 1 byte to 1 MB of UTF-8 text")
    if not re.search(r"\brule\s+[A-Za-z_][A-Za-z_0-9]*", rules):
        raise ValueError("No YARA rule declaration found")
    # The server must parse and compile rules before they are offered to agents.
    yr = os.environ.get("GODSEYE_YARAX_CLI", "yr")
    try:
        with tempfile.TemporaryDirectory(prefix="godseye-edr-") as temp:
            path = os.path.join(temp, "candidate.yar")
            with open(path, "wb") as stream:
                stream.write(raw)
            result = subprocess.run([yr, "compile", "--output", os.path.join(temp, "rules.yarc"), path],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("YARA-X validator unavailable: " + str(exc)) from exc
    if result.returncode:
        raise ValueError("YARA-X rejected rules: " + result.stderr.decode("utf-8", "replace")[:500])
    return hashlib.sha256(raw).hexdigest()
