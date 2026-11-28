"""Model exit changes must not mutate or reload shared browsing routes."""
import copy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import model_selector as selector
from model_relay import RouterRecovery
from tests.test_proxy_provider import load_router, mock_wireguard, proxy_config, write_conf


def options(**kwargs):
    return selector.settings({'model_selector': dict(
        providers=['one', 'two'], domains=['models.example'], **kwargs)},
        {'one': {}, 'two': {}}, 2080)


@pytest.mark.parametrize('field,value', [
    ('providers', ['one', 'one']), ('providers', ['one', 'missing']),
    ('domains', ['bad..example']), ('domains', ['-bad.example']),
    ('domains', ['*.example']), ('control_port', 2080),
    ('control_port', True), ('cooldown_seconds', 0),
])
def test_invalid_settings(field, value):
    config = {'providers': ['one', 'two'], 'domains': ['models.example']}
    config[field] = value
    with pytest.raises(ValueError):
        selector.settings({'model_selector': config}, {'one': {}, 'two': {}}, 2080)


def test_apply_preserves_exits_and_normal_routes():
    config = {'endpoints': [{'type': 'wireguard', 'tag': 'one'}],
              'outbounds': [{'type': 'socks', 'tag': 'two'}],
              'route': {'rules': [{'domain_suffix': ['normal.example'], 'outbound': 'one'}]}}
    before = copy.deepcopy(config)
    selector.apply(config, options(), 'x' * 43)
    assert config['endpoints'] == before['endpoints']
    assert config['outbounds'][:-1] == before['outbounds']
    assert config['route']['rules'][1:] == before['route']['rules']
    assert config['outbounds'][-1]['interrupt_exist_connections'] is False
    assert config['experimental']['clash_api']['external_controller'] == '127.0.0.1:2084'
    assert selector.matches(options(), 'Sub.Models.Example.')
    assert not selector.matches(options(), 'othermodels.example')


def test_insufficient_loaded_exits_refuses_without_mutation():
    config = {'outbounds': [{'tag': 'one'}], 'route': {'rules': []}}
    before = copy.deepcopy(config)
    with pytest.raises(ValueError, match='two loaded exits'):
        selector.apply(config, options(), 'x' * 43)
    assert config == before


def test_secret_is_private_stable_and_validated(tmp_path):
    path = tmp_path / 'state' / 'secret'
    value = selector.secret(path)
    assert selector.secret(path) == value
    assert path.stat().st_mode & 0o777 == 0o600
    path.write_text('invalid')
    with pytest.raises(ValueError):
        selector.secret(path)


@pytest.mark.parametrize('value', [None, [], {'now': 'one', 'all': [None]},
                                        {'now': 'one', 'all': ['two']}])
def test_controller_rejects_invalid_state(value):
    controller = selector.Controller(options(), 'x' * 43)
    controller._request = Mock(return_value=value)
    with pytest.raises(OSError):
        controller.current()


def test_recovery_switches_only_selector_and_stale_errors_do_not_charge(monkeypatch, tmp_path):
    router = SimpleNamespace(
        load_config=lambda: 0, MANUAL_OFF_FILE=tmp_path / 'off',
        network_off_marker=lambda: tmp_path / 'network-off',
        _automatic_proxy_mode=lambda: True, is_proxy_provider=lambda _: True,
        _PROXY_PROFILE_STEM='proxy', rotate=Mock(), engine_reload=Mock(),
        activate_fallback=Mock())
    recovery = RouterRecovery(router, 'models.example')
    state = {'now': 'one', 'all': ['one', 'two']}
    controller = SimpleNamespace(options=options(), current=lambda: state.copy(),
                                 select=lambda name: state.update(now=name))
    monkeypatch.setattr(recovery, '_model_controller', lambda: controller)
    original = recovery.snapshot()
    lease = recovery.upstream_gate.acquire()
    try:
        assert recovery.recover(original)
        assert state['now'] == 'two'
        assert recovery.recover(original)
        assert 'two' not in recovery.model_exit_cooldowns
        assert not recovery.recover(recovery.snapshot())
        assert not recovery.prepare()
    finally:
        recovery.upstream_gate.release(lease)
    router.rotate.assert_not_called()
    router.engine_reload.assert_not_called()
    router.activate_fallback.assert_not_called()

    recovery.model_exit_cooldowns.clear()
    controller.select = Mock(side_effect=OSError('control disconnected'))
    assert not recovery.recover(recovery.snapshot())
    router.rotate.assert_not_called()
    router.engine_reload.assert_not_called()


def test_control_failure_never_uses_global_recovery(monkeypatch, tmp_path):
    router = SimpleNamespace(load_config=lambda: 0, MANUAL_OFF_FILE=tmp_path / 'off',
                             network_off_marker=lambda: tmp_path / 'network-off',
                             _automatic_proxy_mode=lambda: True, rotate=Mock())
    recovery = RouterRecovery(router, 'models.example')
    controller = SimpleNamespace(current=Mock(side_effect=OSError('offline')))
    monkeypatch.setattr(recovery, '_model_controller', lambda: controller)
    assert recovery.snapshot() is None
    assert not recovery.recover(('one', 'one', 'proxy'))
    router.rotate.assert_not_called()


def test_router_build_uses_existing_provider_endpoints(tmp_path):
    router = load_router(tmp_path)
    profile = write_conf(tmp_path / 'providers' / 'proton')
    config = proxy_config()
    config['vpn'] = {'model_selector': {
        'providers': ['proton', 'warp-proxy'], 'domains': ['opencode.ai']}}
    router.CONFIG_FILE.write_text(json.dumps(config))
    assert router.load_config() == 0
    mock_wireguard(router, {'proton': profile})
    generated, selected = router.build_singbox_config()
    assert selected == {'proton': profile}
    assert len(generated['endpoints']) == 1
    model = next(row for row in generated['outbounds'] if row['tag'] == selector.TAG)
    assert model['outbounds'] == ['proton', 'warp-proxy']
    assert generated['route']['rules'][0]['outbound'] == selector.TAG
    router.current_mode = lambda: 'tun'
    with pytest.raises(ValueError, match='proxy mode only'):
        router.build_singbox_config()
