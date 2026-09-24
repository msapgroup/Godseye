from fastapi.testclient import TestClient
from fastapi import HTTPException
import pytest

import app.main as main
from app import site_federation


@pytest.fixture
def client(tmp_path):
    original = main.DB_PATH
    main.DB_PATH = tmp_path / 'sites.db'
    main.init_db()
    try:
        with TestClient(main.app) as api:
            password = 'GODSEYE-site-test-2026!'
            assert api.post('/api/v1/auth/setup', json={'current_password': '', 'new_password': password}).status_code == 200
            assert api.post('/api/v1/auth/login', json={'username': 'admin', 'password': password}).status_code == 200
            yield api
    finally:
        main.DB_PATH = original


def csrf(client):
    return {'X-CSRF-Token': client.cookies['godseye_csrf']}


def test_private_tls_endpoint_validation():
    assert site_federation.validate_endpoint('https://100.82.5.3:8443/') == 'https://100.82.5.3:8443'
    assert site_federation.validate_endpoint('https://192.168.1.50') == 'https://192.168.1.50'
    for address in ('https://8.8.8.8', 'http://192.168.1.50', 'https://127.0.0.1',
                    'https://192.168.1.50/redirect', 'https://user@192.168.1.50'):
        with pytest.raises(HTTPException):
            site_federation.validate_endpoint(address)


def test_one_time_pairing_and_remote_management(client):
    base = '/api/v1/federation'
    assert client.post(base + '/pairing-tokens').status_code in (401, 403)
    result = client.post(base + '/pairing-tokens', headers=csrf(client))
    assert result.status_code == 200, result.text
    token = result.json()['pairing_token']
    with main.db() as c:
        instance = c.execute('SELECT instance_id FROM federation_identity').fetchone()[0]
    pair = client.post(base + '/pair', json={'token': token, 'master_id': 'remote-master', 'master_name': 'Florida Hub'})
    assert pair.status_code == 200, pair.text
    assert pair.json()['instance_id'] == instance
    key = pair.json()['api_key']
    assert client.post(base + '/pair', json={'token': token, 'master_id': 'another'}).status_code == 409
    assert client.get(base + '/summary').status_code == 401
    auth = {'Authorization': 'Bearer ' + key}
    assert client.get(base + '/summary', headers=auth).status_code == 200
    ticket = client.post(base + '/tickets', json={'title': 'Replace battery', 'priority': 'high'}, headers=auth)
    assert ticket.status_code == 200, ticket.text
    assert any(t['id'] == ticket.json()['id'] for t in client.get(base + '/tickets', headers=auth).json())
    closed = client.post(base + f"/tickets/{ticket.json()['id']}/close", json={'note': 'Done'}, headers=auth)
    assert closed.status_code == 200, closed.text
    peers = client.get(base + '/peers').json()
    assert len(peers) == 1 and 'key_hash' not in peers[0]
    assert client.post(base + f"/peers/{peers[0]['id']}/revoke", headers=csrf(client)).status_code == 200
    assert client.get(base + '/summary', headers=auth).status_code == 401


def test_master_links_manages_and_hides_key(client, monkeypatch):
    calls = []
    def remote(endpoint, path, token=None, data=None, method='GET', ca_cert=''):
        calls.append((endpoint, path, token, data, method))
        if path.endswith('/pair'):
            return {'instance_id': 'remote-installation', 'api_key': 'remote-secret'}
        if path.endswith('/summary'):
            return {'instance_id': 'remote-installation', 'devices': 4, 'offline': 1, 'open_findings': 2, 'open_tickets': 1}
        if path.endswith('/devices'):
            return [{'id': 3, 'name': 'Firewall', 'status': 'online'}]
        if path.endswith('/issues') or path.endswith('/tickets'):
            return []
        return {'ok': True}
    monkeypatch.setattr(site_federation, 'remote_call', remote)
    endpoint = '/api/v1/sites'
    created = client.post(endpoint, json={'name': 'Law Office Florida', 'endpoint': 'https://100.89.1.2:8443',
                                          'pairing_token': 'x' * 32}, headers=csrf(client))
    assert created.status_code == 200, created.text
    site_id = created.json()['id']
    assert 'secret' not in str(created.json()) and 'secret' not in str(client.get(endpoint).json())
    assert client.get(endpoint + f'/{site_id}/workspace').json()['devices'][0]['name'] == 'Firewall'
    assert client.patch(endpoint + f'/{site_id}/devices/3', json={'name': 'Edge Firewall', 'classification': 'managed'}, headers=csrf(client)).status_code == 200
    assert client.post(endpoint + f'/{site_id}/tickets', json={'title': 'Check uplink'}, headers=csrf(client)).status_code == 200
    assert all(call[2] == 'remote-secret' for call in calls[1:])
    assert client.delete(endpoint + f'/{site_id}', headers=csrf(client)).status_code == 200
    assert client.get(endpoint).json() == []
