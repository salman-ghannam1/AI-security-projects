#!/usr/bin/python3
"""Run locally in an interactive SSH terminal as root. Never prints secrets."""
import getpass
import grp
import os
import re
import tempfile

if os.geteuid() != 0 or not os.isatty(0):
    raise SystemExit("Run as root in an interactive terminal.")
key = getpass.getpass("OpenRouter API key (hidden): ")
token = getpass.getpass("Telegram bot token (hidden): ")
if not re.fullmatch(r"[A-Za-z0-9_.:-]{20,512}", key):
    raise SystemExit("Invalid OpenRouter key format; nothing saved.")
if not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,200}", token):
    raise SystemExit("Invalid Telegram token format; nothing saved.")
directory = "/etc/wazuh-llm-telegram"
fd, path = tempfile.mkstemp(prefix=".credentials-", dir=directory)
try:
    os.fchmod(fd, 0o640)
    os.fchown(fd, 0, grp.getgrnam("wazuh").gr_gid)
    with os.fdopen(fd, "w") as stream:
        stream.write(f"OPENROUTER_API_KEY={key}\nTELEGRAM_BOT_TOKEN={token}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(path, directory + "/secrets.env")
finally:
    if os.path.exists(path):
        os.unlink(path)
print("Secrets saved securely. No values displayed.")
