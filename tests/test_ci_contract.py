"""Semantic CI/config contract for issue #58."""
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_pytest_configuration_is_canonical_and_strict():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "testpaths = [\"tests\"]" in text
    assert "--strict-markers" in text
    assert "--disable-socket" in text
    assert "error::ResourceWarning" in text
    assert "safety_guard" in text
    assert "enable_socket" in text


def test_dev_requirements_cover_test_runtime():
    requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").lower()
    for package in ("pytest", "pytest-randomly", "pytest-socket", "pyyaml"):
        assert package in requirements


def test_only_reviewed_loopback_harness_enables_sockets():
    text = (ROOT / "tests" / "test_router.py").read_text(encoding="utf-8")
    assert "@pytest.mark.enable_socket\nclass WithProxyTests" in text
    assert 'self._srv.bind(("127.0.0.1", 0))' in text
    assert "self.assertNotEqual(self.port, 2080" in text


def test_workflow_runs_complete_mac_only_pytest_matrix():
    path = ROOT / ".github" / "workflows" / "test.yml"
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True, {}))
    assert "pull_request" in triggers
    assert "push" in triggers
    assert "main" in triggers["push"]["branches"]

    assert set(workflow["jobs"]) == {"test"}
    job = workflow["jobs"]["test"]
    assert job["runs-on"] == "macos-15"
    assert {str(version) for version in job["strategy"]["matrix"]["python-version"]} == {
        "3.10", "3.12",
    }
    assert job["env"]["PROXY_ROUTER_STRICT_HOST_INVARIANTS"] == "1"

    runs = "\n".join(
        step.get("run", "") for step in job["steps"] if isinstance(step, dict)
    )
    assert "pip install -r requirements-dev.txt" in runs
    assert "Install pinned sing-box runtime" in text
    manifest_step = next(
        step for step in job["steps"]
        if isinstance(step, dict) and step.get("name") == "Load pinned sing-box manifest"
    )
    manifest_run = manifest_step["run"]
    assert "sing-box-release.json" in manifest_run
    assert "$GITHUB_ENV" in manifest_run
    assert "SING_BOX_VERSION" in manifest_run
    assert "SING_BOX_SHA_ARM64" in text
    assert "SING_BOX_SHA_AMD64" in text
    runtime_step = next(
        step for step in job["steps"]
        if isinstance(step, dict) and step.get("name") == "Install pinned sing-box runtime"
    )
    assert "env" not in runtime_step
    assert "shasum -a 256 --check -" in runs
    assert '"$bin_dir/sing-box" version' in runs
    assert "python -m pytest tests -q --randomly-seed=58" in runs
    assert "python -m pytest tests -q --randomly-seed=5800" in runs
    assert "unittest discover" not in text
