from pathlib import Path
from fastapi.testclient import TestClient

import app.main as main


def _login_admin(client: TestClient):
    password = "Godseye-v431-Package!Test"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200


def test_package_status_uses_the_versioned_release_when_local_installer_is_absent(tmp_path):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH, main.BASE_DIR = tmp_path / "package.db", tmp_path
    try:
        main.init_db()
        with TestClient(main.app) as client:
            _login_admin(client)
            status = client.get("/api/v1/windows-agents/package-status")
            assert status.status_code == 200
            assert status.json()["available"] is True
            assert status.json()["version"] == "2.4.5"
            response = client.get("/api/v1/windows-agents/package", follow_redirects=False)
            assert response.status_code == 302
            assert response.headers["location"].endswith("GODSEYE-Windows-Agent-x64-Setup-2.4.5.exe")
            assert response.headers["cache-control"].startswith("no-store")
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base


def test_agent_modal_disables_missing_installer_and_handles_download_errors():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert 'id="windowsAgentDownloadBtn"' in source
    assert "loadWindowsAgentPackageStatus" in source
    assert "button.disabled=!info.available" in source
    assert "response.ok" in source
    assert "&fresh='+Date.now()" in source
    assert "GODSEYE-Windows-Agent-x64-Setup-2.4.5.exe" in source


def test_agent_installer_preserves_existing_enrollment():
    script = Path("windows/agent-x64/installer/GODSEYE-Agent-x64.iss").read_text(encoding="utf-8")
    assert "ExistingConfig := ProbeResult = 0" in script
    assert "check-enrollment.ps1" in script
    assert "Result := ExistingConfig" in script
    assert "Enrollment token:" in script
    assert "GODSEYE Windows Agent 2.4.5 was installed and verified successfully" in script


def test_built_agent_installer_is_reported_and_downloaded(tmp_path):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH, main.BASE_DIR = tmp_path / "package.db", tmp_path
    package_dir = tmp_path / "windows" / "agent-x64"
    package_dir.mkdir(parents=True)
    built = package_dir / "GODSEYE-Windows-Agent-x64-Setup-2.4.5.exe"
    built.write_bytes(b"MZ" + b"GODSEYE-AGENT-2.4.5" * 64)
    import json, hashlib
    (package_dir / "setup-manifest.json").write_text(json.dumps({"version":"2.4.5","filename":built.name,"sha256":hashlib.sha256(built.read_bytes()).hexdigest()}))
    try:
        main.init_db()
        with TestClient(main.app) as client:
            _login_admin(client)
            status = client.get("/api/v1/windows-agents/package-status")
            assert status.status_code == 200
            assert status.json()["available"] is True
            response = client.get("/api/v1/windows-agents/package")
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("application/vnd.microsoft.portable-executable")
            assert response.headers["cache-control"].startswith("no-store")
            assert response.headers["x-godseye-agent-version"] == "2.4.5"
            assert 'filename="GODSEYE-Windows-Agent-x64-Setup-2.4.5.exe"' in response.headers["content-disposition"]
            assert response.content == built.read_bytes()
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base
