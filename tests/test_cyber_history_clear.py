from pathlib import Path
import subprocess
from fastapi.testclient import TestClient
from app import main


def test_clear_cyber_history_preserves_other_data_and_requires_admin(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'godseye.db')
    main.init_db()
    password='Strong-test-password-2026!'
    with TestClient(main.app) as admin, TestClient(main.app) as operator:
        assert admin.post('/api/v1/auth/setup',json={'current_password':'','new_password':password}).status_code == 200
        assert admin.post('/api/v1/auth/login',json={'username':'admin','password':password}).status_code == 200
        salt,hashed=main.hash_password(password)
        capture=tmp_path/'capture.pcap';capture.write_bytes(b'capture')
        with main.db() as c:
            c.execute("INSERT INTO users(username,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) VALUES(?,?,?,'operator',0,?,?)",('operator',hashed,salt,main.now(),main.now()))
            c.execute("INSERT INTO network_issues(issue_type,severity,title,first_seen,last_seen) VALUES('cyber_tool','high','Finding',?,?)",(main.now(),main.now()))
            c.execute("INSERT INTO tickets(title,description,status,priority,linked_type,linked_id,created_by,created_at,updated_at) VALUES('Ticket','','open','high','network_finding',1,'admin',?,?)",(main.now(),main.now()))
            c.execute("INSERT INTO cyber_tool_schedules(tool,interval_minutes,created_by,created_at,updated_at,next_run_at) VALUES('web_tls',60,'admin',?,?,?)",(main.now(),main.now(),'2099-01-01'))
            for i in range(35):
                c.execute("INSERT INTO cyber_tool_runs(tool,status,requested_by,started_at,completed_at,finding_id,ticket_id,scheduled_id) VALUES('web_tls','completed','admin',?,?,1,1,1)",(main.now(),main.now()))
        assert operator.post('/api/v1/auth/login',json={'username':'operator','password':password}).status_code == 200
        endpoint='/api/v1/cyber-tools/runs/clear'
        assert operator.post(endpoint,headers={'X-CSRF-Token':operator.cookies['godseye_csrf']}).status_code == 403
        assert len(admin.get('/api/v1/cyber-tools/runs?limit=30').json()) == 30
        assert admin.get('/api/v1/cyber-tools/runs/1/export').status_code == 200
        response=admin.post(endpoint,headers={'X-CSRF-Token':admin.cookies['godseye_csrf']})
        assert response.status_code == 200 and response.json()['deleted'] == 35
        assert admin.get('/api/v1/cyber-tools/runs').json() == []
        assert admin.get('/api/v1/cyber-tools/runs/1/export').status_code == 404
        with main.db() as c:
            for table in ('network_issues','tickets','cyber_tool_schedules'):
                assert c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]==1
            assert c.execute("SELECT COUNT(*) FROM audit_log WHERE action='cyber_tool_history_cleared'").fetchone()[0]==1
        assert capture.read_bytes() == b'capture'


def test_clear_history_ui_confirms_and_refreshes():
    source=Path('app/main.py').read_text()
    assert 'id="clearCyberHistoryBtn" type="button" class="danger admin-only"' in source
    fn=source[source.index('async function clearCyberHistory()'):source.index('async function loadCyberSchedules()')]
    script="""
const assert=require('node:assert/strict');
const CYBER_LAST_RUN={web_tls:{id:1}};let accepted=false,called=0,refreshed=0;
const button={disabled:false},actions={innerHTML:'buttons',classList:{remove(){}}};
const document={getElementById:id=>id==='clearCyberHistoryBtn'?button:actions};
const confirm=()=>accepted,alert=()=>{};
async function json(url,options){called++;assert.equal(url,'/api/v1/cyber-tools/runs/clear');assert.equal(options.method,'POST');return {deleted:35}}
async function loadCyberHistory(){refreshed++}
"""+fn+"""
(async()=>{await clearCyberHistory();assert.equal(called,0);accepted=true;await clearCyberHistory();assert.equal(called,1);assert.equal(refreshed,1);assert.equal(CYBER_LAST_RUN.web_tls,undefined);assert.equal(button.disabled,false);assert.equal(actions.innerHTML,'')})().catch(e=>{console.error(e);process.exit(1)});
"""
    result=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr
