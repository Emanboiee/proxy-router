"""Disk-full failures before commit preserve the previous private state."""
import errno
import json
import stat

import pytest

import router
import state


@pytest.mark.parametrize("writer", ["state", "engine"])
@pytest.mark.parametrize("stage", ["create", "write", "close", "chmod", "replace"])
def test_disk_full_preserves_previous_file(tmp_path, monkeypatch, writer, stage):
    target = tmp_path / "sing-box.json"
    original = '{"validated": true}\n'
    target.write_text(original)
    target.chmod(0o600)
    committed = []
    monkeypatch.setattr(router, "SING_BOX_CONFIG", target)
    monkeypatch.setattr(router, "_hand_back_ownership", committed.append)
    real_temporary = state.tempfile.NamedTemporaryFile

    def no_space(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "injected disk full")

    class FailingFile:
        def __init__(self, *args, **kwargs):
            self.file = real_temporary(*args, **kwargs)

        def __enter__(self):
            self.file.__enter__()
            self.name = self.file.name
            return self

        def write(self, text):
            if stage == "write":
                self.file.write(text[:5])
                no_space()
            return self.file.write(text)

        def __exit__(self, *args):
            result = self.file.__exit__(*args)
            if stage == "close":
                no_space()
            return result

    if stage == "create":
        monkeypatch.setattr(state.tempfile, "NamedTemporaryFile", no_space)
    elif stage in {"write", "close"}:
        monkeypatch.setattr(state.tempfile, "NamedTemporaryFile", FailingFile)
    else:
        monkeypatch.setattr(state.os, stage, no_space)

    with pytest.raises(OSError) as failure:
        if writer == "engine":
            router.write_sing_box({"endpoints": [{"type": "wireguard", "tag": "fixture"}]})
        else:
            state.atomic_write(target, "new state", on_commit=committed.append)
    assert failure.value.errno == errno.ENOSPC
    assert target.read_text() == original
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [target]
    assert committed == []


def test_engine_writer_commits_private_json_before_ownership_callback(tmp_path, monkeypatch):
    target = tmp_path / "state" / "sing-box.json"
    payload = {"outbounds": [{"type": "socks", "tag": "fixture"}]}
    seen = []
    monkeypatch.setattr(router, "SING_BOX_CONFIG", target)
    monkeypatch.setattr(router, "_hand_back_ownership", lambda path: seen.append(json.loads(path.read_text())))
    router.write_sing_box(payload)
    assert seen == [payload]
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(target.parent.iterdir()) == [target]
