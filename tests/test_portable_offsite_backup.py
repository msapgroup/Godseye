import json
import sqlite3
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app import main, offsite_backup


def test_unmounted_path_is_rejected(tmp_path):
    with pytest.raises(ValueError, match='not a mounted'):
        offsite_backup.validate_share(str(tmp_path))


def test_scheduled_bundle_retention_and_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'app.db');main.init_db()
    key=tmp_path/'secret.key';key.write_bytes(b'example-appliance-key')
    share=tmp_path/'share';share.mkdir()
    monkeypatch.setattr(offsite_backup,'validate_share',lambda path:share)
    with main.db() as c:
        main.ensure_ir_schema(c);main.ensure_hardening_schema(c);main.ensure_production_schema(c)
        offsite_backup.ensure_schema(c)
        c.execute("UPDATE portable_backup_settings SET share_path=?,keep_count=1 WHERE id=1",(str(share),))
        c.execute("INSERT INTO network_issues(issue_type,severity,title,first_seen,last_seen) VALUES('test','high','Original',?,?)",(main.now(),main.now()))
    other=share/'godseye-full-other-server-20260101T020000000000Z.zip';other.write_bytes(b'other')
    mgr=offsite_backup.OffsiteBackupManager(main.db,main.DB_PATH,key,main.config_export)
    first=mgr.run();second=mgr.run()
    assert not (share/first['filename']).exists() and (share/second['filename']).exists() and other.exists()
    with zipfile.ZipFile(share/second['filename']) as z:
        assert set(z.namelist())=={'database.db','secret.key','settings.json','manifest.json'}
        assert z.testzip() is None and z.read('secret.key')==key.read_bytes()
        snapshot=tmp_path/'restore.db';snapshot.write_bytes(z.read('database.db'))
        with sqlite3.connect(snapshot) as c:assert c.execute("SELECT title FROM network_issues").fetchone()[0]=='Original'
        assert json.loads(z.read('manifest.json'))['format']=='godseye-full-backup'
    monkeypatch.setattr(offsite_backup,'validate_share',lambda path: (_ for _ in ()).throw(ValueError('share offline')))
    with pytest.raises(ValueError,match='offline'):mgr.run()
    with main.db() as c:
        state=offsite_backup.settings(c)
        assert 'share offline' in state['last_error'] and state['last_success_at']
        assert c.execute("SELECT count(*) FROM portable_backup_history WHERE status='failed'").fetchone()[0]==1
    assert (share/second['filename']).exists()


def test_admin_reminders_settings_and_permissions(tmp_path,monkeypatch):
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'godseye.db');main.init_db()
    password='GODSEYE-strong-test-2026!'
    with TestClient(main.app) as admin, TestClient(main.app) as operator:
        assert admin.post('/api/v1/auth/setup',json={'current_password':'','new_password':password}).status_code==200
        assert admin.post('/api/v1/auth/login',json={'username':'admin','password':password}).status_code==200
        headers={'X-CSRF-Token':admin.cookies['godseye_csrf']}
        salt,hashed=main.hash_password(password)
        with main.db() as c:c.execute("INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) VALUES(?,?,?,'operator',0,?,?)",('operator',hashed,salt,main.now(),main.now()))
        assert operator.post('/api/v1/auth/login',json={'username':'operator','password':password}).status_code==200
        assert operator.get('/api/v1/appliance/portable-backup').status_code==403
        assert operator.post('/api/v1/appliance/portable-backup/download-started',headers={'X-CSRF-Token':operator.cookies['godseye_csrf']}).status_code==403
        state=admin.get('/api/v1/appliance/portable-backup').json()
        assert state['download_overdue'] and state['enabled']==0
        assert admin.put('/api/v1/appliance/portable-backup',headers=headers,json={'reminder_days':0}).status_code==400
        assert admin.put('/api/v1/appliance/portable-backup',headers=headers,json={'enabled':True,'share_path':str(tmp_path)}).status_code==400
        assert admin.post('/api/v1/appliance/portable-backup/download-started',headers=headers).status_code==200
        assert not admin.get('/api/v1/appliance/portable-backup').json()['download_overdue']


def test_offsite_bundle_can_be_restored_through_real_import(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    from app import appliance_hardening as hardening
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'server.db')
    monkeypatch.setattr(main,'KEY_PATH',tmp_path/'secret.key')
    monkeypatch.setattr(main,'BACKUP_DIR',tmp_path/'backups')
    monkeypatch.setattr(hardening,'KEY_PATH',main.KEY_PATH)
    monkeypatch.setattr(hardening,'BACKUP_DIR',main.BACKUP_DIR)
    main.KEY_PATH.write_bytes(Fernet.generate_key())
    share=tmp_path/'share';share.mkdir()
    monkeypatch.setattr(offsite_backup,'validate_share',lambda path:share)
    main.init_db()
    with TestClient(main.app) as admin:
        password='GODSEYE-strong-test-2026!'
        assert admin.post('/api/v1/auth/setup',json={'current_password':'','new_password':password}).status_code==200
        assert admin.post('/api/v1/auth/login',json={'username':'admin','password':password}).status_code==200
        headers={'X-CSRF-Token':admin.cookies['godseye_csrf']}
        with main.db() as c:
            c.execute("INSERT INTO network_issues(issue_type,severity,title,first_seen,last_seen) VALUES('test','high','Before backup',?,?)",(main.now(),main.now()))
        result=admin.post('/api/v1/appliance/portable-backup/run',headers=headers)
        assert result.status_code==200, result.text
        contents=(share/result.json()['filename']).read_bytes()
        with main.db() as c:c.execute("UPDATE network_issues SET title='Changed after backup'")
        response=admin.post('/api/v1/appliance/backups/import',content=contents,headers={**headers,'Content-Type':'application/zip'})
        assert response.status_code==200,response.text
        with main.db() as c:assert c.execute('SELECT title FROM network_issues').fetchone()[0]=='Before backup'
