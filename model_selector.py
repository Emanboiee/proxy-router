"""Opt-in model-only routing over already-loaded exits, without engine reloads."""
from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path
import urllib.request

TAG = "model-egress"


def settings(vpn, providers, proxy_port):
    value = vpn.get("model_selector")
    if value is None or value is False:
        return None
    if not isinstance(value, dict):
        raise ValueError("vpn.model_selector must be an object")
    names = value.get("providers", [])
    domains = value.get("domains", [])
    port = value.get("control_port", 2084)
    cooldown = value.get("cooldown_seconds", 900)
    if (not isinstance(names, list) or len(names) < 2
            or any(not isinstance(name, str) or name not in providers for name in names)
            or len(set(names)) != len(names)):
        raise ValueError("model_selector.providers needs at least two distinct known providers")
    if (not isinstance(domains, list) or not domains
            or any(not isinstance(domain, str) or len(domain) > 253
                   or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+', domain)
                   for domain in domains)):
        raise ValueError("model_selector.domains needs explicit domain names")
    if type(port) is not int or not 1 <= port <= 65535 or port in (proxy_port, 2082, 8090):
        raise ValueError("model_selector.control_port must be a separate private control port")
    if type(cooldown) is not int or not 1 <= cooldown <= 86400:
        raise ValueError("model_selector.cooldown_seconds must be 1..86400")
    return {"providers": names, "domains": [domain.lower() for domain in domains],
            "control_port": port, "cooldown_seconds": cooldown}


def secret(path: Path):
    try:
        value = path.read_text().strip()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation avoids overwriting another controller's credential.
        try:
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
                output.write(secrets.token_urlsafe(32) + '\n')
        except FileExistsError:
            pass
        value = path.read_text().strip()
    if not 32 <= len(value) <= 256 or any(c not in
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in value):
        raise ValueError("invalid model selector control credential")
    path.chmod(0o600)
    return value


def matches(config, host):
    host = host.lower().rstrip('.')
    return any(host == domain or host.endswith('.' + domain) for domain in config['domains'])


def apply(config, options, credential):
    available = {row['tag'] for key in ('outbounds', 'endpoints') for row in config.get(key, [])}
    if TAG in available:
        raise ValueError("reserved model-egress outbound tag already exists")
    members = [name for name in options['providers'] if name in available]
    if len(members) < 2:
        raise ValueError("model selector needs at least two loaded exits; no extra tunnels are started")
    existing = config.get('experimental', {}).get('clash_api')
    api = {"external_controller": f"127.0.0.1:{options['control_port']}", "secret": credential}
    if existing and existing != api:
        raise ValueError("model selector conflicts with the existing Clash API configuration")
    config.setdefault('experimental', {})['clash_api'] = api
    config['outbounds'].append({"type": "selector", "tag": TAG, "outbounds": members,
                                "default": members[0], "interrupt_exist_connections": False})
    config['route']['rules'].insert(0, {"domain_suffix": options['domains'], "outbound": TAG})
    return config


class Controller:
    def __init__(self, options, credential):
        self.options = options
        self.url = f"http://127.0.0.1:{options['control_port']}/proxies/{TAG}"
        self.credential = credential
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, method, value=None):
        body = json.dumps(value).encode() if value is not None else None
        request = urllib.request.Request(self.url, data=body, method=method, headers={
            'Authorization': 'Bearer ' + self.credential, 'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=3) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise OSError('oversized selector control response')
        try:
            return json.loads(raw) if raw else None
        except (ValueError, UnicodeError) as exc:
            raise OSError('invalid selector control response') from exc

    def current(self):
        value = self._request('GET')
        if (not isinstance(value, dict) or value.get('now') not in self.options['providers']
                or not isinstance(value.get('all'), list)
                or any(not isinstance(name, str) for name in value['all'])
                or value['now'] not in value['all']):
            raise OSError('invalid model selector state')
        return value

    def select(self, provider):
        state = self.current()
        if provider not in state['all'] or provider not in self.options['providers']:
            raise ValueError('provider is absent from the loaded model selector')
        self._request('PUT', {'name': provider})
        if self.current()['now'] != provider:
            raise OSError('model selector did not confirm the requested exit')
