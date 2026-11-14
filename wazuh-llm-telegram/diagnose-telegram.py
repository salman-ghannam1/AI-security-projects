#!/usr/bin/python3
"""Read-only Telegram diagnostics. Prints only allowlisted status and bot username."""
import json
import os
import re
import urllib.error
import urllib.request

from integration import config, NoRedirect

cfg = config()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
for method, body in [('getMe', {}), ('getChat', {'chat_id': cfg['chat_id']})]:
    request = urllib.request.Request(
        'https://api.telegram.org/bot' + os.environ['TELEGRAM_BOT_TOKEN'] + '/' + method,
        json.dumps(body).encode(), {'Content-Type': 'application/json'}, method='POST')
    try:
        with opener.open(request, timeout=cfg['http_timeout']) as response:
            data = json.loads(response.read(16384))
        print(method + ': ' + ('OK' if data.get('ok') else 'API rejected'))
        if method == 'getMe' and data.get('ok'):
            username = data.get('result', {}).get('username', '')
            if re.fullmatch(r'[A-Za-z0-9_]{5,32}', username):
                print('Bot username: ' + username)
    except urllib.error.HTTPError as error:
        try:
            description = json.loads(error.read(16384)).get('description', '').lower()
        except Exception:
            description = ''
        allowed = ['chat not found', 'bot was blocked', 'user is deactivated',
                   'unauthorized', 'not found', "bot can't initiate"]
        reason = next((text for text in allowed if text in description), 'request rejected')
        print(method + ': HTTP ' + str(error.code) + ' - ' + reason)
        error.close()
    except Exception:
        print(method + ': network/TLS/timeout failure')
