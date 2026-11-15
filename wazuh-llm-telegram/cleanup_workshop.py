#!/usr/bin/python3
"""Remove only artifacts owned by one workshop run. Keeps evidence/backups."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess


def run(*args, check=True):
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=check)


def matching_keys(db, manifest, ident):
    keys = []
    for key, payload in db.execute('SELECT key,payload FROM queue'):
        alert = json.loads(payload)
        log = alert.get('full_log', '')
        associated = key in manifest.get('production_queue_keys', []) or f'run_id={ident} ' in log
        if associated and 'WORKSHOP TEST — SYNTHETIC EVENT' in log and str(alert.get('rule', {}).get('id')) in {str(i) for i in range(118500, 118506)}:
            keys.append(key)
    return keys


def cleanup(manifest_path, dry_run=False):
    if os.geteuid() != 0:
        raise RuntimeError('Root required')
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    ident = manifest['run_id']
    if not re.fullmatch(r'workshop-\d{8}T\d{6}Z-[0-9a-f]{6}', ident):
        raise RuntimeError('Invalid run identity')
    root = Path('/root/wazuh-workshop') / ident
    state = Path('/var/lib/wazuh-workshop') / ident
    code = Path('/opt/wazuh-workshop') / ident
    if manifest_path.resolve() != root / 'manifest.json':
        raise RuntimeError('Manifest must remain at the original protected location')
    for path in (root, state, code):
        if path.exists() and (path.is_symlink() or path.resolve() != path):
            raise RuntimeError('Unsafe artifact path')
    ossec = Path('/var/ossec/etc/ossec.conf')
    rules = Path('/var/ossec/etc/rules/workshop_test_rules.xml')
    testlog = Path('/var/log/wazuh-workshop-test.log')
    original = ossec.read_text()
    block = manifest['localfile_block']
    expected_begin = '  <!-- WORKSHOP TEST LOCALFILE BEGIN run=' + ident + ' -->'
    if not block.startswith(expected_begin) or '<location>/var/log/wazuh-workshop-test.log</location>' not in block:
        raise RuntimeError('Unexpected cleanup block')
    if block not in original:
        raise RuntimeError('Exact test localfile block missing or changed; refusing broad edits')
    rule_text = rules.read_text() if rules.exists() else None
    if rules.is_symlink() or testlog.is_symlink():
        raise RuntimeError('Refusing symlink artifacts')
    if rule_text and hashlib.sha256(rule_text.encode()).hexdigest() != manifest['rule_sha256']:
        raise RuntimeError('Rule file changed; refusing deletion')
    if testlog.exists():
        for line in testlog.read_text().splitlines():
            if line and ('WORKSHOP TEST — SYNTHETIC EVENT' not in line or f'run_id={ident} ' not in line):
                raise RuntimeError('Log contains data outside this run')
    if dry_run:
        cfg = json.loads(Path('/etc/wazuh-llm-telegram/config.json').read_text())
        db = sqlite3.connect('file:' + cfg['database'] + '?mode=ro', uri=True)
        keys = matching_keys(db, manifest, ident)
        db.close()
        print(json.dumps({'dry_run': True, 'run_id': ident, 'production_queue_rows': len(keys),
                          'rules': str(rules), 'log': str(testlog), 'exact_localfile_block': True,
                          'isolated_directories': [str(state), str(code)], 'preserve_evidence_and_backups': True}))
        return
    backup = root / 'ossec.conf.pre-cleanup'
    shutil.copy2(ossec, backup)
    os.chmod(backup, 0o600)
    ossec.write_text(original.replace(block, '', 1))
    if rules.exists():
        rules.unlink()
    try:
        run('/var/ossec/bin/wazuh-analysisd', '-t')
        run('/var/ossec/bin/wazuh-logcollector', '-t')
    except Exception:
        ossec.write_text(original)
        if rule_text is not None:
            rules.write_text(rule_text)
            import grp
            os.chown(rules, 0, grp.getgrnam('wazuh').gr_gid)
            os.chmod(rules, 0o640)
        raise RuntimeError('Validation failed; test configuration restored') from None
    active = subprocess.run(['/bin/systemctl', 'is-active', '--quiet', 'wazuh-llm-telegram']).returncode == 0
    run('/bin/systemctl', 'stop', 'wazuh-workshop-fallback-' + ident, check=False)
    if active:
        run('/bin/systemctl', 'stop', 'wazuh-llm-telegram')
    try:
        # This is the actual production database, never an arbitrary manifest path.
        cfg = json.loads(Path('/etc/wazuh-llm-telegram/config.json').read_text())
        db = sqlite3.connect(cfg['database'], timeout=15)
        with db:
            keys = matching_keys(db, manifest, ident)
            for key in keys:
                db.execute('DELETE FROM ai_calls WHERE key=?', (key,))
                db.execute('DELETE FROM receipts WHERE key=?', (key,))
                db.execute('DELETE FROM queue WHERE key=?', (key,))
        db.close()
        run('/bin/systemctl', 'restart', 'wazuh-manager')
        testlog.unlink(missing_ok=True)
        for directory in (state, code):
            if directory.exists():
                shutil.rmtree(directory)
    finally:
        if active:
            run('/bin/systemctl', 'start', 'wazuh-llm-telegram')
    print('Removed only this run: test rules, test log, exact localfile block, matching production queue/audit rows, and isolated test directories.')
    print('Preserved: real alerts.json, indexed alerts, production integration/configuration/secrets, Hermes, Telegram messages, evidence and backups.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', default=str(Path(__file__).resolve().with_name('manifest.json')))
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        cleanup(args.manifest, args.dry_run)
    except Exception as error:
        print('Cleanup stopped safely: ' + type(error).__name__)
        raise SystemExit(1)
