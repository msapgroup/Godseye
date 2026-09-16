from pathlib import Path
import hashlib
import subprocess

from app.windows_agent import load_update_manifest

ROOT=Path(__file__).resolve().parents[1]


def test_v428_release_marker_and_clean_root():
    assert (ROOT/'VERSION').read_text().strip()=='4.28.0-clean-rebuild'
    assert (ROOT/'V4.28_RELEASE_NOTES.md').exists()
    assert not (ROOT/'windows/agent').exists()
    assert not (ROOT/'.github/scripts/apply_v423_remote_access.py').exists()


def test_release_is_local_zip_install_not_clone_workflow():
    install=(ROOT/'install.sh').read_text()
    readme=(ROOT/'README.md').read_text()
    assert '\ngit clone ' not in install and '\nsudo git clone ' not in install
    assert 'sudo bash ./install.sh --fresh' in readme
    assert 'rsync -a --delete "$SRC_DIR/app/" "$STAGE_DIR/app/"' in install
    assert 'PYTHONPATH="$INSTALL_DIR"' in install
    assert 'ROLLBACK_DIR' in install and 'restoring previous GODSEYE application files' in install


def test_staged_update_reuses_main_installer():
    helper=(ROOT/'godseye-apply-update').read_text()
    assert 'exec bash "$ROOT/install.sh" --upgrade' in helper
    assert 'rsync -a --delete' not in helper


def test_windows_agent_packages_use_one_canonical_contract():
    d=ROOT/'windows/agent-x64'
    manifest=load_update_manifest(d/'update-manifest.json')
    assert manifest['filename']=='GODSEYE-Windows-Agent-x64.msi'
    assert manifest['setup_filename']=='GODSEYE-Windows-Agent-x64-Setup.exe'
    assert manifest['sha256']==(d/'GODSEYE-Windows-Agent-x64.msi.sha256').read_text().strip().upper()
    assert manifest['setup_sha256']==(d/'GODSEYE-Windows-Agent-x64-Setup.exe.sha256').read_text().strip().upper()
    for name, digest in ((manifest['filename'], manifest['sha256']),
                         (manifest['setup_filename'], manifest['setup_sha256'])):
        package=d/name
        if package.exists():
            assert hashlib.sha256(package.read_bytes()).hexdigest().upper()==digest
    assert not (d/'GODSEYE-Agent-x64.msi').exists()
    assert not (d/'GODSEYE-Agent-x64-Setup.exe').exists()


def test_stale_agent_packages_are_not_tracked():
    if not (ROOT/'.git').exists():
        return
    packages=('GODSEYE.Agent.exe', 'GODSEYE-Windows-Agent-x64.msi',
              'GODSEYE-Windows-Agent-x64-Setup.exe')
    tracked=subprocess.check_output(
        ['git', 'ls-files', '--', *(f'windows/agent-x64/{name}' for name in packages)],
        cwd=ROOT, text=True)
    assert tracked == ''


def test_agent_source_workflow_and_installer_names_match():
    d=ROOT/'windows/agent-x64'
    cs=(d/'src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj').read_text()
    wix=(d/'installer/msi/Package.wxs').read_text()
    iss=(d/'installer/GODSEYE-Agent-x64.iss').read_text()
    workflow=(ROOT/'.github/workflows/build-windows-agent.yml').read_text()
    assert '<AssemblyName>GODSEYE.Agent</AssemblyName>' in cs
    assert '<RuntimeIdentifier>win-x64</RuntimeIdentifier>' in cs
    assert '<PlatformTarget>x64</PlatformTarget>' in cs
    assert 'GODSEYE.Agent.exe' in wix
    assert '#define MyMsiName "GODSEYE-Windows-Agent-x64.msi"' in iss
    assert 'GODSEYE.Agent.exe' in workflow
    assert 'GODSEYE.WindowsAgent.exe' not in workflow
    assert 'v4.23' not in workflow


def test_server_has_no_legacy_agent_package_route():
    source=(ROOT/'app/main.py').read_text()
    assert '/windows-agents/package/legacy' not in source
    assert 'GODSEYE-Windows-Agent-x64-Setup.exe' in source
    assert 'GODSEYE-Windows-Agent-x64.msi' in (ROOT/'app/windows_agent.py').read_text()


def test_clean_release_validator_present():
    validator=(ROOT/'scripts/validate_release.py').read_text()
    assert 'GODSEYE release validation: PASS' in validator
    assert 'legacy script-built Windows agent directory must not be shipped' in validator


def test_clean_installer_preserves_venv_executables_and_uses_checked_in_units():
    install=(ROOT/'install.sh').read_text()
    assert 'find "$INSTALL_DIR" -path "$INSTALL_DIR/.venv" -prune' in install
    assert 'chmod -R g+rX,o-rwx "$INSTALL_DIR/.venv"' in install
    assert 'install -m 0644 "$INSTALL_DIR/godseye-web.service" /etc/systemd/system/godseye-web.service' in install
    assert 'install -m 0644 "$INSTALL_DIR/godseye-scanner.service" /etc/systemd/system/godseye-scanner.service' in install
    assert 'cat >/etc/systemd/system/godseye-web.service' not in install
    assert 'cat >/etc/systemd/system/godseye-scanner.service' not in install


def test_clean_rebuild_audit_documented():
    cleanup=(ROOT/'docs/V4.28_CLEANUP.md').read_text()
    assert 'legacy script-compiled Windows Agent' in cleanup
    assert 'explicit allow-list' in cleanup
    assert 'PNG signatures and chunk CRCs' in cleanup
