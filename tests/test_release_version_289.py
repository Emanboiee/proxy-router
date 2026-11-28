from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def test_source_bundle_stamps_release_tag_and_checksum():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert 'printf \'%s\\n\' "${GITHUB_REF_NAME}" > dist/proxy-router/VERSION' in workflow
    assert 'sha256sum "proxy-router-${GITHUB_REF_NAME}-source.tar.gz"' in workflow
    assert 'proxy-router-${{ github.ref_name }}-source.tar.gz.sha256' in workflow
