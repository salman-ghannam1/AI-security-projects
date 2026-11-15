# Wazuh → OpenRouter → Telegram

Single-node lab integration in `wazuh-llm-telegram/`. No secrets belong in this repository.

Wazuh invokes `custom-llm-telegram`, a shell wrapper that only runs the Python
queue producer. The producer accepts integer alert levels 12–16 only, labels
12–14 HIGH and 15–16 CRITICAL, redacts data, and commits it to SQLite. The manager
configuration also filters at level 12. A separate systemd worker running as
`wazuh` performs HTTPS calls to OpenRouter and Telegram. No AI recommendations
are executed. Existing Hermes/Telegram configuration is not read or modified.

## Deploy

Review the code first. Python 3.9+ and systemd are required; only the Python standard
library is used. Run as root on the Wazuh manager:

```sh
python3 -m unittest discover -s wazuh-llm-telegram -v
python3 wazuh-llm-telegram/integration.py --selftest-filter
python3 wazuh-llm-telegram/install.py stage
python3 /opt/wazuh-llm-telegram/setup_secrets.py
python3 wazuh-llm-telegram/install.py activate
runuser -u wazuh -- python3 /opt/wazuh-llm-telegram/integration.py test
```

The setup program prompts with `getpass` in an interactive terminal. Never put
keys or tokens in shell arguments, chat, Git, logs, or shell history. It atomically
writes `/etc/wazuh-llm-telegram/secrets.env` as `root:wazuh 0640`.
Activation backs up `ossec.conf`, removes only previous integration blocks with
this exact name, adds one block, and validates with `wazuh-analysisd -t` and
`wazuh-integratord -t` before restarting the manager. Invalid configuration is
restored without restarting. An activation failure restores and validates the
previous configuration before restarting it. Other Wazuh services, firewall
rules, SSH, VMware, Hermes and Telegram settings are not changed.

`/etc/wazuh-llm-telegram/config.json` controls the model (default
`openai/gpt-4o-mini`), destination chat ID, intervals, retries and queue limits.
After changing it or secrets, restart only `wazuh-llm-telegram.service`.

## Reliability and privacy

- SQLite WAL with FULL synchronization and unique SHA-256 identity derived from
  alert ID/agent/rule; missing IDs additionally use the complete event hash.
- One worker holds an OS advisory lock. Pending jobs survive worker restarts.
- AI failures retry with exponential backoff then produce an alert with
  `AI analysis unavailable` and generic triage recommendations.
- Telegram failures retry with backoff, jitter and server retry hints. Completed
  multipart positions persist. Exhausted jobs remain `dead` for operator review;
  they are never silently deleted. Pending/dead capacity is configurable.
- Default rate limits: one AI request per 2 seconds, one Telegram message per
  1.2 seconds. Timestamps persist across restarts. Telegram messages use plain
  text, disable link previews, and split conservatively below 4096 UTF-16 units.
- Delivery is **at least once**, not exactly once: a crash after Telegram accepts
  a message but before SQLite commits can duplicate that part. IDs permit correlation.
- Deduplication is retained for 30 days after successful delivery; older sent
  records are pruned hourly. Pending and dead records are retained.
- Redaction covers sensitive JSON keys, password/token assignments, common key
  formats, bearer tokens, email addresses, private keys and card-like numbers.
  Unlabeled opaque strings of 32+ characters are also redacted. Arbitrary secrets
  in free text cannot be recognized perfectly; review your event sources.
- Redaction runs before persistent queue storage, before AI calls, and before
  Telegram sends. Selected event details are limited to 6000 characters and AI
  input to 18000. AI output has a strict JSON schema plus local validation.
- Alert text is explicitly untrusted input, with no tools or command execution.
  Prompt injection cannot authorize actions. AI hypotheses still require human review.
- Only fixed HTTPS API hosts are used; redirects and environment proxies are
  disabled. Exceptions and response bodies are never logged. Alerts leave the
  lab for OpenRouter/provider analysis and Telegram delivery.

## Operations

```sh
systemctl status wazuh-llm-telegram --no-pager
journalctl -u wazuh-llm-telegram --since '15 minutes ago' --no-pager
runuser -u wazuh -- python3 /opt/wazuh-llm-telegram/integration.py status
```

Logs show generic status and counts only. For a dead job, stop the worker, inspect
the redacted local database securely, resolve the underlying failure, and reset
only the selected job's status/attempts/due. Do not reset `next_part` unless you
intend to repeat previously delivered parts. Back up the SQLite database with
SQLite's backup API rather than copying a live WAL database's main file alone.

For a read-only token/chat check without printing secrets, run the diagnostic
script in a transient service with the same user and environment file:

```sh
systemd-run --quiet --wait --pipe -p User=wazuh -p Group=wazuh \
  -p EnvironmentFile=/etc/wazuh-llm-telegram/secrets.env \
  /usr/bin/python3 /opt/wazuh-llm-telegram/diagnose-telegram.py
```

It prints only allowlisted API statuses and the public bot username. `getMe: OK`
with `getChat: HTTP 400 - chat not found` usually requires opening that bot from
the destination account and pressing Start, or correcting the configured chat ID.
It does not send any messages or consume updates belonging to another bot client.

## Synthetic real-pipeline workshop

`workshop.py` runs six marked syslog events through a dedicated monitored file,
custom rules 118500–118505, Wazuh logcollector/analysisd/integratord and the normal
worker. It refuses occupied rule IDs or existing test files, backs up the manager
configuration, runs all six cases through `wazuh-logtest`, validates analysisd and
logcollector, and restarts only the manager before appending events eight seconds
apart. It never writes to `alerts.json` and never calls the integration producer
for the main events.

```sh
sudo python3 wazuh-llm-telegram/workshop.py
```

The workshop sends four normal synthetic alert notifications and one isolated
AI-unavailable fallback notification to the configured chat. The duplicate replay
uses an actual workshop alert but only a separate queue, with no worker/network
calls. The failure exercise copies the integration, uses its own configuration,
SQLite database and transient systemd worker, and changes only that copy's
`OR_URL` to the unreachable HTTPS loopback endpoint `https://127.0.0.1:1/unreachable`.
It expects three failed AI attempts then a real Telegram fallback delivery.

The queue keeps metadata-only `ai_calls` and `receipts` tables for correlation:
request attempt/outcome timestamps, queue key, Telegram message ID/part/chat and
delivery timestamp. No API keys or bot tokens are recorded. A receipt is written
only after a successful API response containing an integer message ID. Those
audit rows expire along with successfully completed queue records.

Each run stores evidence and a protected cleanup manifest under
`/root/wazuh-workshop/<run-id>/`, isolated code under
`/opt/wazuh-workshop/<run-id>/`, and isolated databases under
`/var/lib/wazuh-workshop/<run-id>/`. The copied `cleanup.py` can be run as root
after reviewing evidence. It checks rule hashes and exact localfile markers,
refuses non-test log lines or symlinks, validates before restarting, and removes
only that run's test rules/log/localfile/queue/audit rows and isolated directories.
It keeps reports/backups, indexed alerts, real `alerts.json`, production
integration/secrets, Telegram messages and Hermes. The workshop does **not** run
cleanup automatically.

Telegram delivery evidence is API acceptance and returned message IDs; the tool
does not claim that a person visually inspected Telegram. The injection case also
compares the reconstructed message to the real secrets inside a transient
unprivileged process, reporting booleans only. AI recommendations are never executed.

To disable: stop/disable only `wazuh-llm-telegram`, restore the appropriate
`ossec.conf.llm-backup-*` file, validate with `wazuh-analysisd -t` and
`wazuh-integratord -t`, then restart the manager. Keep the queue and secrets for
review or explicit cleanup. Never commit deployment state or credentials.

Official references: [Wazuh integrations](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html),
[OpenRouter API](https://openrouter.ai/docs/api_reference/overview),
[Telegram sendMessage](https://core.telegram.org/bots/api#sendmessage).
