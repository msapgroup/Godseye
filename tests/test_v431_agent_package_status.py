from pathlib import Path
import shutil

from fastapi.testclient import TestClient

import app.main as main


def _login_admin(client: TestClient):
    password = "Godseye-v431-Package!Test"
    assert client.post("/api/v1/auth/setup", json={"current_password": "", "new_password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": password}).status_code == 200


def test_package_status_reports_pending_instead_of_substituting_legacy_binary(tmp_path):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH, main.BASE_DIR = tmp_path / "package.db", tmp_path
    try:
        main.init_db()
        with TestClient(main.app) as client:
            _login_admin(client)
            status = client.get("/api/v1/windows-agents/package-status")
            assert status.status_code == 200
            assert status.json()["available"] is False
            assert "legacy installer is not substituted" in status.json()["message"]
            assert client.get("/api/v1/windows-agents/package").status_code == 404
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base


def test_agent_modal_disables_missing_installer_and_handles_download_errors():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert 'id="windowsAgentDownloadBtn"' in source
    assert "loadWindowsAgentPackageStatus" in source
    assert "button.disabled=!info.available" in source
    assert "response.ok" in source


def test_agent_installer_always_explains_enrollment_choice():
    script = Path("windows/agent-x64/installer/GODSEYE-Agent-x64.nsi").read_text(encoding="utf-8")
    assert "Page custom EnrollmentPageCreate EnrollmentPageLeave" in script
    assert "Keep existing GODSEYE enrollment" in script
    assert "An existing GODSEYE enrollment was found" in script
    assert 'Delete "$APPDATA\\GODSEYE\\Agent\\agent.key"' in script


def test_built_agent_installer_is_reported_and_downloaded(tmp_path):
    old_db, old_base = main.DB_PATH, main.BASE_DIR
    main.DB_PATH, main.BASE_DIR = tmp_path / "package.db", tmp_path
    package_dir = tmp_path / "windows" / "agent-x64"
    package_dir.mkdir(parents=True)
    built = Path("windows/agent-x64/GODSEYE-Windows-Agent-x64-Setup.exe")
    shutil.copy2(built, package_dir / built.name)
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
            assert response.content == built.read_bytes()
    finally:
        main.DB_PATH, main.BASE_DIR = old_db, old_base
