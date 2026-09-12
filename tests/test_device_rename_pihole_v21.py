import io
import json
import urllib.error
from unittest.mock import patch


def test_rename_ui_is_available_in_inventory_and_device_page():
    from app import main
    assert 'id="renameDeviceModal"' in main.DASHBOARD
    assert 'function openRenameDevice(' in main.DASHBOARD
    assert "${x.name?'Rename':'Name'}" in main.DASHBOARD
    detail = main.device_detail_page(3).body.decode()
    assert 'Rename Device' in detail
    assert 'function renameCurrentDevice()' in detail


def test_device_name_can_be_set_and_renamed(tmp_path):
    from app import main
    from fastapi.testclient import TestClient

    old = main.DB_PATH
    main.DB_PATH = tmp_path / 'rename.db'
    try:
        main.init_db()
        with TestClient(main.app) as client:
            password = 'Godseye-Test-2026!Strong'
            assert client.post('/api/v1/auth/setup', json={'current_password':'','new_password':password}).status_code == 200
            assert client.post('/api/v1/auth/login', json={'username':'admin','password':password}).status_code == 200
            with main.db() as c:
                c.execute("INSERT INTO devices(mac,ip,hostname,vendor,name,device_type,status,first_seen,last_seen,classification) VALUES(?,?,?,?,?,?,?,?,?,?)",
                          ('aa:bb:cc:dd:ee:01','192.168.1.50','unknown-host','Vendor',None,'unknown','online',main.now(),main.now(),'new'))
                device_id = c.execute("SELECT id FROM devices WHERE mac=?",('aa:bb:cc:dd:ee:01',)).fetchone()[0]
            csrf = client.cookies.get('godseye_csrf')
            r = client.patch(f'/api/v1/devices/{device_id}', headers={'X-CSRF-Token':csrf}, json={'name':'  Living Room TV  '})
            assert r.status_code == 200
            d = client.get(f'/api/v1/devices/{device_id}').json()
            assert d['name'] == 'Living Room TV'
            r = client.patch(f'/api/v1/devices/{device_id}', headers={'X-CSRF-Token':csrf}, json={'name':'Media Room TV'})
            assert r.status_code == 200
            assert client.get(f'/api/v1/devices/{device_id}').json()['name'] == 'Media Room TV'
    finally:
        main.DB_PATH = old


class FakeResponse:
    def __init__(self, data, status=200):
        self.payload = json.dumps(data).encode()
        self.status = status
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, *_):
        return self.payload
    def geturl(self):
        return 'https://pi.hole/'


def test_pihole_v6_application_password_is_exchanged_for_sid():
    from app.integrations import pihole_test
    seen = []
    def fake_urlopen(req, timeout=8, context=None):
        seen.append(req)
        if req.full_url.endswith('/api/auth'):
            assert req.get_method() == 'POST'
            assert json.loads(req.data.decode()) == {'password':'app-password'}
            return FakeResponse({'session':{'valid':True,'sid':'SID123','csrf':'CSRF123','validity':300}})
        if req.full_url.endswith('/api/info/version'):
            assert req.get_header('X-ftl-sid') == 'SID123'
            return FakeResponse({'version':{'core':{'local':{'version':'v6'}}}})
        raise AssertionError(req.full_url)
    with patch('app.integrations.urllib.request.urlopen', side_effect=fake_urlopen):
        result = pihole_test('https://pi.hole', credential='app-password', verify_tls=False)
    assert result['ok'] is True
    assert result['auth_mode'] == 'v6_session'
    assert len(seen) == 2


def test_pihole_legacy_static_token_fallback():
    from app.integrations import pihole_test
    def http_error(url, code, body=''):
        return urllib.error.HTTPError(url, code, 'error', {}, io.BytesIO(body.encode()))
    def fake_urlopen(req, timeout=8, context=None):
        if req.full_url.endswith('/api/auth'):
            raise http_error(req.full_url, 404, 'not found')
        if 'auth=legacy-token' in req.full_url:
            return FakeResponse({'version':'legacy'})
        raise http_error(req.full_url, 401, 'unauthorized')
    with patch('app.integrations.urllib.request.urlopen', side_effect=fake_urlopen):
        result = pihole_test('http://pi.hole', credential='legacy-token')
    assert result['ok'] is True
    assert result['auth_mode'] == 'legacy_token'
