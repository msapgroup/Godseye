import sqlite3
import subprocess

import pytest

from app import integration_reporting, main, scanner


@pytest.mark.parametrize('module', [main, scanner])
def test_connections_close_after_commit_and_rollback(tmp_path, monkeypatch, module):
    monkeypatch.setattr(module, 'DB_PATH', tmp_path / 'test.db')
    with module.db() as connection:
        connection.execute('CREATE TABLE data (value TEXT)')
        connection.execute("INSERT INTO data VALUES ('saved')")
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute('SELECT 1')
    with pytest.raises(ValueError):
        with module.db() as connection:
            connection.execute("INSERT INTO data VALUES ('rolled back')")
            raise ValueError('rollback')
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute('SELECT 1')
    with module.db() as connection:
        assert [row[0] for row in connection.execute('SELECT value FROM data')] == ['saved']


def test_pihole_network_wait_does_not_block_database_writers(tmp_path, monkeypatch):
    path = tmp_path / 'godseye.db'
    monkeypatch.setattr(main, 'DB_PATH', path)
    main.init_db()
    with main.db() as c:
        integration_reporting.ensure_schema(c)
        c.execute("INSERT INTO integration_configs(kind,enabled,target,created_at,updated_at) VALUES('pihole',1,'http://pi','x','x')")
    monkeypatch.setattr(integration_reporting, 'pihole_client_observations', lambda *a, **kw: {'ok': True, 'observations': [{'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.0.2.1'}]})
    def analytics(*args, **kwargs):
        writer = sqlite3.connect(path, timeout=0)
        try:
            writer.execute('BEGIN IMMEDIATE')
            writer.rollback()
        finally:
            writer.close()
        return {'ok': True}
    monkeypatch.setattr(integration_reporting, 'pihole_analytics', analytics)
    with main.db() as c:
        result = integration_reporting.sync_integration(c, 'pihole')
    assert result['ok'], result
    assert result['observations'] == 1


def test_login_messages_distinguish_server_failure_from_credentials():
    source = open('app/main.py', encoding='utf-8').read()
    handlers = '\n'.join(line for line in source.splitlines() if line.startswith(('async function doLogin(', 'async function doMfaVerify(')))
    script = '''
const assert = require('node:assert/strict');
const fields = {loginErr:{textContent:''}, mfaLoginErr:{textContent:''}};
const document = {getElementById:id => fields[id]};
const loginUser={value:'admin'},loginPass={value:'secret'},mfaCode={value:'123456'};
let PENDING_MFA_TOKEN='test', response;
const fetch=async()=>{if(response instanceof Error)throw response;return response};
''' + handlers + '''
(async()=>{
 for (const [status, expected] of [[401,'Invalid username'],[423,'Account temporarily locked'],[429,'Too many'],[500,'server could not'],[503,'server could not']]) {
   response={status,ok:false};await doLogin({preventDefault(){}});assert(fields.loginErr.textContent.includes(expected),fields.loginErr.textContent);
 }
 response=new Error('offline');await doLogin({preventDefault(){}});assert(fields.loginErr.textContent.includes('Unable to reach'));
 response={status:503,ok:false};await doMfaVerify({preventDefault(){}});assert(fields.mfaLoginErr.textContent.includes('server could not'));
 response={status:401,ok:false};await doMfaVerify({preventDefault(){}});assert(fields.mfaLoginErr.textContent.includes('Invalid code'));
})().catch(e=>{console.error(e);process.exit(1)});
'''
    result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
