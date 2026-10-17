import pytest
from fastapi.testclient import TestClient
from app import main, scanner
from app.intelligence import correlate_device
from app.discovery_intelligence import ingest_observations
from app.traffic_intelligence import _device_for


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    path = tmp_path / 'devices.db'
    monkeypatch.setattr(main, 'DB_PATH', path)
    monkeypatch.setattr(scanner, 'DB_PATH', path)
    monkeypatch.setattr(scanner, 'resolve_hostname', lambda ip: 'discovered-host')
    monkeypatch.setattr(scanner, 'ping_reachable', lambda ip: False)
    main.init_db()
    scanner.init_db()
    return path


def scan(mac='02:11:22:33:44:55', ip='192.0.2.5'):
    return scanner.record_scan([{'mac': mac, 'ip': ip, 'vendor': 'Discovery vendor'}])


def saved():
    with main.db() as c:
        return dict(c.execute('SELECT * FROM devices ORDER BY id').fetchone())


def login(client):
    password = 'Device-Persistence-Test!2026'
    assert client.post('/api/v1/auth/setup', json={'current_password': '', 'new_password': password}).status_code == 200
    assert client.post('/api/v1/auth/login', json={'username': 'admin', 'password': password}).status_code == 200
    return {'X-CSRF-Token': client.cookies.get('godseye_csrf')}


def customize(client, headers, device_id):
    fields = {'name': 'Office TV', 'hostname': 'office-tv', 'device_type': 'TV',
              'classification': 'managed', 'notes': 'Reception wall', 'icon_key': 'tv',
              'icon_data': 'data:image/png;base64,aGVsbG8='}
    assert client.patch(f'/api/v1/devices/{device_id}', headers=headers, json=fields).status_code == 200
    return fields


def test_saved_edits_survive_offline_restart_mac_format_and_dhcp_change(inventory):
    scan()
    before = saved()
    with TestClient(main.app) as client:
        headers = login(client)
        fields = customize(client, headers, before['id'])
    for _ in range(scanner.OFFLINE_THRESHOLD + 1):
        scanner.record_scan([])
    assert saved()['status'] == 'offline'
    # Reopen the same database, as both services do after a restart/upgrade.
    main.init_db(); scanner.init_db()
    scan('02-11-22-33-44-55', '192.0.2.90')
    with main.db() as c:
        correlate_device(c, '0211.2233.4455', '192.0.2.90', 'other-host', source='dhcp')
        assert c.execute('SELECT count(*) FROM devices').fetchone()[0] == 1
    after = saved()
    assert all(after[k] == v for k, v in fields.items())
    assert after['id'] == before['id'] and after['first_seen'] == before['first_seen']
    assert after['status'] == 'online' and after['ip'] == '192.0.2.90'


def test_explicit_private_address_link_retains_identity_history_and_deletion_resets(inventory):
    scan(); original = saved()
    with TestClient(main.app) as client:
        headers = login(client)
        fields = customize(client, headers, original['id'])
        scan('06:11:22:33:44:66', '192.0.2.99')
        route = f"/api/v1/devices/{original['id']}/remember-address"
        assert client.post(route, json={'mac': '06:11:22:33:44:66'}).status_code == 403
        r = client.post(route, headers=headers, json={'mac': '06:11:22:33:44:66'})
        assert r.status_code == 200, r.text
        for _ in range(scanner.OFFLINE_THRESHOLD + 1): scanner.record_scan([])
        scanner.init_db()
        scan('06:11:22:33:44:66', '192.0.2.100')
        with main.db() as c:
            ingest_observations(c, 'dhcp', [{'mac': '06:11:22:33:44:66', 'ip': '192.0.2.100', 'hostname': 'new-dns-name'}], gateway='192.0.2.1')
            assert c.execute('SELECT count(*) FROM devices').fetchone()[0] == 1
            assert c.execute('SELECT count(*) FROM events WHERE mac=?', (original['mac'],)).fetchone()[0] >= 3
            assert not c.execute('SELECT 1 FROM topology_links WHERE child=?', ('06:11:22:33:44:66',)).fetchone()
            assert _device_for(c, '06:11:22:33:44:66', '192.0.2.100')[0] == original['id']
        after = saved()
        assert all(after[k] == v for k, v in fields.items())
        assert after['id'] == original['id'] and after['ip'] == '192.0.2.100'
        # Deleting the remembered device removes its aliases as well.
        assert client.request('DELETE', f"/api/v1/devices/{original['id']}", headers=headers, json={'reason': 'Device retired'}).status_code == 200
        scan('06:11:22:33:44:66')
        assert saved()['name'] is None and saved()['icon_key'] == 'auto'
        with main.db() as c:
            assert c.execute('SELECT count(*) FROM device_mac_aliases').fetchone()[0] == 0


def test_ip_reuse_does_not_transfer_saved_details_or_rescue_old_device(inventory, monkeypatch):
    scan(); original = saved()
    with main.db() as c:
        c.execute("UPDATE devices SET name='Original TV',icon_key='tv' WHERE id=?", (original['id'],))
    monkeypatch.setattr(scanner, 'ping_reachable', lambda ip: True)
    for _ in range(scanner.OFFLINE_THRESHOLD + 1): scan('06:11:22:33:44:66')
    with main.db() as c:
        rows = list(c.execute('SELECT * FROM devices ORDER BY id'))
        assert rows[0]['status'] == 'offline' and rows[0]['name'] == 'Original TV'
        assert rows[1]['name'] is None and rows[1]['icon_key'] == 'auto'
        assert _device_for(c, '0a:11:22:33:44:77', original['ip'])[0] is None


def test_link_conflicts_do_not_overwrite_other_saved_devices(inventory):
    scan(); original = saved()
    scan('06:11:22:33:44:66', '192.0.2.99')
    with TestClient(main.app) as client:
        headers = login(client)
        with main.db() as c:
            other = c.execute('SELECT id FROM devices WHERE mac=?', ('06:11:22:33:44:66',)).fetchone()[0]
        customize(client, headers, other)
        route = f"/api/v1/devices/{original['id']}/remember-address"
        for mac in ('06:11:22:33:44:66', 'ff:ff:ff:ff:ff:ff', 'not-a-mac'):
            assert client.post(route, headers=headers, json={'mac': mac}).status_code == 409
        assert len(client.get('/api/v1/devices').json()) == 2


def test_legacy_mac_spelling_is_reused_without_reset(inventory):
    scan()
    with main.db() as c:
        c.execute("UPDATE devices SET mac='02-11-22-33-44-55',name='Legacy TV',icon_key='tv'")
    scan('02:11:22:33:44:55')
    with main.db() as c:
        assert c.execute('SELECT count(*) FROM devices').fetchone()[0] == 1
    assert saved()['name'] == 'Legacy TV' and saved()['status'] == 'online'


def test_explicit_empty_hostname_stays_empty_and_hostname_edits_block_consolidation(inventory):
    scan(); original = saved()
    with TestClient(main.app) as client:
        headers = login(client)
        assert client.patch(f"/api/v1/devices/{original['id']}", headers=headers, json={'hostname': ''}).status_code == 200
        with main.db() as c:
            correlate_device(c, original['mac'], hostname='automatic-name', source='dhcp')
        assert saved()['hostname'] == ''
        scan('06:11:22:33:44:66', '192.0.2.99')
        with main.db() as c:
            other = c.execute('SELECT id FROM devices WHERE mac=?', ('06:11:22:33:44:66',)).fetchone()[0]
        assert client.patch(f'/api/v1/devices/{other}', headers=headers, json={'hostname': 'custom-host'}).status_code == 200
        assert client.post(f"/api/v1/devices/{original['id']}/remember-address", headers=headers, json={'mac': '06:11:22:33:44:66'}).status_code == 409


def test_repeated_observations_in_one_scan_do_not_create_duplicates(inventory):
    scanner.record_scan([
        {'mac': '02:11:22:33:44:55', 'ip': '192.0.2.5', 'vendor': 'Demo'},
        {'mac': '02-11-22-33-44-55', 'ip': '192.0.2.5', 'vendor': 'Demo'},
    ])
    with main.db() as c:
        assert c.execute('SELECT count(*) FROM devices').fetchone()[0] == 1
