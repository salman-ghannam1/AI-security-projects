#!/usr/bin/python3
"""Idempotent staging/activation. Run as root; does not change firewall rules."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import subprocess

SOURCE = Path(__file__).resolve().parent
DEST = Path('/opt/wazuh-llm-telegram')
ETC = Path('/etc/wazuh-llm-telegram')
STATE = Path('/var/lib/wazuh-llm-telegram')
OSSEC = Path('/var/ossec/etc/ossec.conf')
UNIT = 'wazuh-llm-telegram.service'
NAME = 'custom-llm-telegram'


def run(*args):
    # Do not capture/print configuration contents or raw subprocess errors.
    result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        raise RuntimeError('Command failed: ' + args[0])


def copy_file(source, target, mode, gid):
    shutil.copyfile(source, target)
    os.chown(target, 0, gid)
    os.chmod(target, mode)


def stage():
    import grp
    import pwd
    gid = grp.getgrnam('wazuh').gr_gid
    uid = pwd.getpwnam('wazuh').pw_uid
    for directory in (DEST, ETC, STATE):
        directory.mkdir(parents=True, exist_ok=True)
        os.chown(directory, uid if directory == STATE else 0, gid)
        os.chmod(directory, 0o750)
    for filename in ('integration.py', 'setup_secrets.py', 'diagnose-telegram.py'):
        copy_file(SOURCE / filename, DEST / filename, 0o750, gid)
    if not (ETC / 'config.json').exists():
        copy_file(SOURCE / 'config.json', ETC / 'config.json', 0o640, gid)
    copy_file(SOURCE / NAME, Path('/var/ossec/integrations') / NAME, 0o750, gid)
    copy_file(SOURCE / 'wazuh-llm-telegram.service', Path('/etc/systemd/system') / UNIT, 0o644, 0)
    run('/usr/sbin/runuser', '-u', 'wazuh', '--', '/usr/bin/python3', str(DEST / 'integration.py'), 'init')
    run('/bin/systemctl', 'daemon-reload')
    print('Staged. Worker is not started and ossec.conf is unchanged.')


def integration_config(text):
    # Wazuh supports multiple ossec_config roots: preserve the existing file layout.
    pattern = re.compile(r'<integration\b[^>]*>.*?</integration\s*>', re.S)
    def remove_match(match):
        return '' if re.search(r'<name>\s*custom-llm-telegram\s*</name>', match[0]) else match[0]
    text = pattern.sub(remove_match, text)
    block = '\n  <integration>\n    <name>custom-llm-telegram</name>\n    <level>12</level>\n    <alert_format>json</alert_format>\n  </integration>\n'
    if '</ossec_config>' not in text:
        raise ValueError('Missing ossec_config closing tag')
    return text.replace('</ossec_config>', block + '</ossec_config>', 1)


def activate():
    import grp
    secrets = ETC / 'secrets.env'
    stat = secrets.stat()
    if stat.st_uid != 0 or stat.st_gid != grp.getgrnam('wazuh').gr_gid or stat.st_mode & 0o777 != 0o640 or stat.st_size == 0:
        raise RuntimeError('Invalid secrets file ownership/mode')
    run('/usr/bin/python3', str(DEST / 'integration.py'), '--selftest-filter')
    original = OSSEC.read_text()
    updated = integration_config(original)
    backup = Path(str(OSSEC) + '.llm-backup-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    shutil.copy2(OSSEC, backup)
    os.chmod(backup, 0o600)
    try:
        OSSEC.write_text(updated)
        run('/var/ossec/bin/wazuh-analysisd', '-t')
        run('/var/ossec/bin/wazuh-integratord', '-t')
    except Exception:
        OSSEC.write_text(original)
        raise RuntimeError('Validation failed; original configuration restored') from None
    try:
        run('/bin/systemctl', 'enable', UNIT)
        run('/bin/systemctl', 'restart', UNIT)
        run('/bin/systemctl', 'restart', 'wazuh-manager')
        run('/bin/systemctl', 'is-active', UNIT, 'wazuh-manager')
    except Exception:
        OSSEC.write_text(original)
        run('/var/ossec/bin/wazuh-analysisd', '-t')
        subprocess.run(['/bin/systemctl', 'stop', UNIT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run('/bin/systemctl', 'restart', 'wazuh-manager')
        raise RuntimeError('Activation failed; original manager configuration restored') from None
    print('Activated. Backup: ' + str(backup))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['stage', 'activate'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Root required')
    os.umask(0o077)
    try:
        stage() if args.mode == 'stage' else activate()
    except Exception:
        raise SystemExit('Deployment step failed. No secrets printed; check service/configuration status.')
