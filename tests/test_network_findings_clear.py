from fastapi.testclient import TestClient
from app import main


def test_network_finding_clear_categories_and_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'findings.db')
    main.init_db()
    password = 'Strong-test-password-2026!'
    with TestClient(main.app) as admin, TestClient(main.app) as operator:
        assert admin.post('/api/v1/auth/setup', json={'current_password':'', 'new_password':password}).status_code == 200
        assert admin.post('/api/v1/auth/login', json={'username':'admin','password':password}).status_code == 200
        headers={'X-CSRF-Token':admin.cookies['godseye_csrf']}
        salt, hashed=main.hash_password(password)
        with main.db() as c:
            c.execute("INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) VALUES(?,?,?,'operator',0,?,?)", ('operator',hashed,salt,main.now(),main.now()))
            for i in range(205):
                c.execute("INSERT INTO network_issues(issue_type,severity,title,status,first_seen,last_seen) VALUES('test',? ,?,?,?,?)", ('critical' if i == 0 else 'medium',f'resolved-{i}','resolved',main.now(),main.now()))
            c.execute("INSERT INTO network_issues(issue_type,severity,title,status,first_seen,last_seen) VALUES('test','high','open-high','open',?,?)",(main.now(),main.now()))
            c.execute("INSERT INTO network_issues(issue_type,severity,title,status,first_seen,last_seen) VALUES('test','medium','open-medium','open',?,?)",(main.now(),main.now()))
            first=c.execute("SELECT id FROM network_issues WHERE title='resolved-0'").fetchone()[0]
            c.execute("INSERT INTO tickets(title,description,status,priority,linked_type,linked_id,created_by,created_at,updated_at) VALUES('Ticket','','open','high','network_finding',?,'admin',?,?)",(first,main.now(),main.now()))
            c.execute("INSERT INTO cyber_tool_runs(tool,status,requested_by,started_at,completed_at,finding_id) VALUES('test','completed','admin',?,?,?)",(main.now(),main.now(),first))
        assert operator.post('/api/v1/auth/login',json={'username':'operator','password':password}).status_code == 200
        op_headers={'X-CSRF-Token':operator.cookies['godseye_csrf']}
        endpoint='/api/v1/intelligence/issues-clear'
        assert operator.post(endpoint,headers=op_headers,json={'category':'all'}).status_code == 403
        assert admin.post(endpoint,headers=headers,json={'category':'open'}).status_code == 400
        counts=admin.get('/api/v1/intelligence/issues-summary').json()
        assert counts == {'total':207,'open_count':2,'resolved_count':205,'critical_count':2}
        assert len(admin.get('/api/v1/intelligence/issues?status=resolved').json()) == 200
        result=admin.post(endpoint,headers=headers,json={'category':'resolved'})
        assert result.status_code == 200 and result.json()['deleted']==205
        with main.db() as c:
            assert c.execute('SELECT linked_type FROM tickets').fetchone()[0]=='network_finding_deleted'
            assert c.execute('SELECT finding_id FROM cyber_tool_runs').fetchone()[0] is None
            assert c.execute("SELECT COUNT(*) FROM audit_log WHERE action='network_findings_cleared'").fetchone()[0]==1
        result=admin.post(endpoint,headers=headers,json={'category':'critical'})
        assert result.json()['deleted']==1
        assert admin.get('/api/v1/intelligence/issues-summary').json()['open_count']==1
        assert admin.post(endpoint,headers=headers,json={'category':'all'}).json()['deleted']==1
        assert admin.get('/api/v1/intelligence/issues-summary').json()['total']==0
