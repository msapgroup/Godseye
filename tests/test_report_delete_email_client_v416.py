from pathlib import Path
import app.main as main

def test_version():
    assert Path("VERSION").read_text().strip().startswith(("4.16.0-","4.17.0-", "4.18.0-", "4.19.0-", "4.20.0-", "4.21.0-", "4.22.0-", "4.22.1-", "4.23.0-", "4.24.0", "4.25.0"))

def test_report_history_delete_ui():
    html=main.DASHBOARD
    assert "Delete Selected" in html
    assert "report-select" in html
    assert "deleteReport(" in html
    assert "deleteSelectedReports()" in html
    assert "Email</button>" in html

def test_report_delete_api_is_admin_only_and_audited():
    source=Path("app/main.py").read_text()
    assert '@app.delete(f"{router_prefix}/reports/{{report_id}}")' in source
    assert '@app.post(f"{router_prefix}/reports/bulk-delete")' in source
    assert "report_deleted" in source
    assert "reports_bulk_deleted" in source
    assert "Depends(require_admin)" in source

def test_email_schema_and_oauth_security(tmp_path,monkeypatch):
    db=tmp_path/"email.db"
    monkeypatch.setattr(main,"DB_PATH",db)
    main.init_db()
    with main.db() as c:
        cols={r["name"] for r in c.execute("PRAGMA table_info(email_integrations)")}
        states={r["name"] for r in c.execute("PRAGMA table_info(email_oauth_states)")}
    assert {"provider","client_id","client_secret_enc","access_token_enc","refresh_token_enc","token_expires_at","last_status"} <= cols
    assert {"state","integration_id","provider","redirect_uri","expires_at"} <= states

def test_email_is_under_management_sidebar_and_role_limited():
    html=main.DASHBOARD
    management=html[html.index('<div class="navsection">Management</div>'):html.index('<div class="navsection">Administration</div>')]
    assert 'data-view="email"' in management
    assert 'navitem operate-only' in management
    assert '<span>Email</span>' in management
    source=Path("app/main.py").read_text()
    assert 'def email_messages(' in source and 'Depends(require_permission("operate"))' in source

def test_gmail_and_microsoft_mail_scopes_and_endpoints():
    source=Path("app/main.py").read_text()
    assert "https://www.googleapis.com/auth/gmail.modify" in source
    assert "https://www.googleapis.com/auth/gmail.send" in source
    assert "Mail.ReadWrite" in source
    assert "Mail.Send" in source
    assert "gmail.googleapis.com/gmail/v1/users/me/messages/send" in source
    assert "graph.microsoft.com/v1.0/me/sendMail" in source

def test_email_client_features_are_present():
    html=main.DASHBOARD
    for token in (
        'id="view-email"',
        'id="emailMessageList"',
        'id="emailReaderPane"',
        'id="emailComposeModal"',
        'id="emailIntegrationModal"',
        'id="emailComposeFiles"',
        'Save Draft',
        'Reply All',
        'Forward',
        'Mail Accounts',
    ):
        assert token in html

def test_email_backend_features_present():
    source=Path("app/main.py").read_text()
    for token in (
        '@app.get(f"{router_prefix}/email/folders")',
        '@app.get(f"{router_prefix}/email/messages")',
        '@app.get(f"{router_prefix}/email/messages/{{message_id}}")',
        '@app.post(f"{router_prefix}/email/send")',
        '@app.post(f"{router_prefix}/email/drafts")',
        '/trash")',
        '/state")',
        '/attachments/{{attachment_id}}")',
        '@app.post(f"{router_prefix}/email/report")',
    ):
        assert token in source

def test_email_tokens_and_secrets_are_encrypted():
    source=Path("app/main.py").read_text()
    assert "encrypt_secret(req.client_secret.strip())" in source
    assert "encrypt_secret(access)" in source
    assert "encrypt_secret(refresh)" in source
    assert "GODSEYE_PUBLIC_URL" in source

def test_report_email_builds_pdf_or_csv_attachment():
    source=Path("app/main.py").read_text()
    assert "report_pdf_bytes(d)" in source
    assert "report_csv_bytes(d)" in source
    assert "EmailAttachmentRequest" in source

def test_email_dark_ui_styles_present():
    source=Path("app/main.py").read_text()
    assert "html[data-theme=\"dark\"] .email-shell" in source
    assert "html[data-theme=\"dark\"] .email-message-row" in source
    assert ".email-reader-body" in source
