import base64
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
import app.main as main


def test_remote_access_routes_and_ui_present():
    src=Path("app/main.py").read_text()
    html=main.DASHBOARD
    assert "/remote-access/sessions" in src
    assert "/windows-agents/remote/sessions/" in src
    assert 'data-view="remote-access"' in html
    assert "Remote Access" in html and "signed-in Windows user must approve" in html
    assert "remote_session_start" in src and "remote_session_stop" in src

def test_remote_agent_has_full_desktop_control_after_approval_and_no_shell():
    src=Path("windows/agent-x64/src/Godseye.WindowsAgent/GodseyeAgentService.cs").read_text()
    cs=Path("windows/agent-x64/src/Godseye.WindowsAgent/Godseye.WindowsAgent.csproj").read_text()
    assert '<Version>2.2.15</Version>' in cs
    assert 'MessageBox' in src and 'requesting to view and control this computer' in src
    assert 'WTSQueryUserToken' in src and 'CreateProcessAsUser' in src
    assert 'NamedPipeServerStream' in src and 'CopyFromScreen' in src
    assert 'SetCursorPos' in src and 'mouse_event' in src and 'keybd_event' in src
    assert 'MOUSEEVENTF_WHEEL' in src
    assert 'cmd.exe' not in src.lower()
    assert 'powershell.exe' not in src.lower()
    assert 'remote_session_start' in src


def _remote_agent_and_session():
    ts=main.now()
    with main.db() as c:
        agent_id=c.execute("""INSERT INTO windows_agents
            (agent_uuid,api_key_hash,computer_name,agent_version,status,last_heartbeat_at,enrolled_at,updated_at)
            VALUES('remote-test','remote-key','GMRS','2.2.15','online',?,?,?)""",(ts,ts,ts)).lastrowid
        session_id=c.execute("""INSERT INTO windows_remote_sessions(agent_id,status,requested_by,requested_at)
            VALUES(?,'connecting','admin',?)""",(agent_id,ts)).lastrowid
    return agent_id,session_id


def test_remote_frame_uses_writable_data_directory_and_activates_session(tmp_path,monkeypatch):
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'godseye.db')
    main.init_db()
    agent_id,session_id=_remote_agent_and_session()
    jpeg=b'\xff\xd8\xff\xd9'
    main.windows_remote_agent_frame(session_id,main.WindowsRemoteFrameRequest(
        image_base64=base64.b64encode(jpeg).decode(),width=10,height=10),agent={'id':agent_id})
    assert (tmp_path/'remote-frames'/f'session-{session_id}.jpg').read_bytes()==jpeg
    with main.db() as c:
        row=c.execute('SELECT status,connected_at FROM windows_remote_sessions WHERE id=?',(session_id,)).fetchone()
    assert row['status']=='active' and row['connected_at']


def test_failed_remote_command_and_stalled_session_do_not_leave_approval_pending(tmp_path,monkeypatch):
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'godseye.db')
    main.init_db()
    agent_id,session_id=_remote_agent_and_session()
    with main.db() as c:
        command_id=c.execute("""INSERT INTO windows_agent_commands(agent_id,command_type,payload_json,status,requested_by,requested_at)
            VALUES(?,'remote_session_start',?,'delivered','admin',?)""",
            (agent_id,json.dumps({'session_id':session_id}),main.now())).lastrowid
    request=SimpleNamespace(client=SimpleNamespace(host='127.0.0.1'))
    main.windows_agent_command_result(command_id,main.WindowsAgentCommandResult(
        ok=False,details='Approved, but no interactive desktop was available'),request,agent={'id':agent_id})
    with main.db() as c:
        row=c.execute('SELECT status,last_error FROM windows_remote_sessions WHERE id=?',(session_id,)).fetchone()
    assert row['status']=='failed' and 'interactive desktop' in row['last_error']

    old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=5)).isoformat()
    with main.db() as c:
        c.execute("UPDATE windows_remote_sessions SET status='connecting',requested_at=?,last_error='' WHERE id=?",(old,session_id))
        c.execute("UPDATE windows_agent_commands SET status='pending' WHERE id=?",(command_id,))
    result=main.windows_remote_start(main.WindowsRemoteStartRequest(agent_id=agent_id),request,user={'username':'admin'})
    assert result['session']['id'] != session_id
    with main.db() as c:
        old_session=c.execute('SELECT status FROM windows_remote_sessions WHERE id=?',(session_id,)).fetchone()
        old_command=c.execute('SELECT status FROM windows_agent_commands WHERE id=?',(command_id,)).fetchone()
    assert old_session['status']=='failed' and old_command['status']=='failed'
