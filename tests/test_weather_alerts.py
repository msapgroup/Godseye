from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest
import app.main as main
from app import weather_alerts as weather


def test_weather_storage_permissions_and_source_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'weather.db')
    main.init_db()
    pw = 'Weather-Admin!Strong2026'
    with TestClient(main.app) as client:
        assert client.get('/api/v1/weather/cities').status_code == 401
        assert client.post('/api/v1/auth/setup', json={'new_password':pw,'current_password':''}).status_code == 200
        assert client.post('/api/v1/auth/login', json={'username':'admin','password':pw}).status_code == 200
        headers={'X-CSRF-Token':client.cookies.get('godseye_csrf')}
        assert client.get('/').headers['x-frame-options'] == 'DENY'
        assert client.get('/assets/weather/index.html').headers['x-frame-options'] == 'SAMEORIGIN'
        assert client.get('/api/v1/weather/tiles/bad/2/1/1').status_code == 422
        assert client.get('/api/v1/weather/tiles/imagery/2/99/1').status_code == 422
        result=client.get('/api/v1/weather/cities').json()
        assert result['can_manage'] and [c['name'] for c in result['cities']] == ['Tampa','Buffalo']
        assert client.put('/api/v1/weather/cities',json={'cities':[]}).status_code == 403
        assert client.put('/api/v1/weather/cities',headers=headers,json={'cities':[]}).status_code == 200
        assert client.get('/api/v1/weather/cities').json()['cities'] == []
        assert client.put('/api/v1/weather/cities',headers=headers,json={'cities':weather.DEFAULT_CITIES*2}).status_code == 422
        assert client.get('/api/v1/weather/zip/bad').status_code == 422
        assert client.get('/api/v1/weather/points?lat=nan&lon=0').status_code == 422
        assert client.get('/api/v1/weather/stations/bad.url/observations/latest').status_code == 422
        called=[]
        def fake(url,ttl=180):
            called.append(url)
            return {'features':[]} if '/alerts/' in url else {'properties':{'observationStations':'https://attacker.example/stations'}}
        monkeypatch.setattr(weather,'provider_json',fake)
        assert client.get('/api/v1/weather/alerts?lat=27.95&lon=-82.45').status_code == 200
        assert called[-1] == 'https://api.weather.gov/alerts/active?point=27.9500,-82.4500'
        assert client.get('/api/v1/weather/points?lat=27.95&lon=-82.45').status_code == 502
        assert len(called) == 2  # no request to an arbitrary URL supplied in a provider response
        salt,hashed=main.hash_password(pw)
        with main.db() as c:
            c.execute('INSERT INTO users(username,display_name,password_hash,password_salt,role,must_change_password,created_at,password_changed_at) VALUES(?,?,?,?,?,0,?,?)',('weather-reader','Reader',hashed,salt,'readonly',main.now(),main.now()))
        client.post('/api/v1/auth/logout',headers=headers)
        client.post('/api/v1/auth/login',json={'username':'weather-reader','password':pw})
        headers={'X-CSRF-Token':client.cookies.get('godseye_csrf')}
        r=client.get('/api/v1/weather/cities').json()
        assert not r['can_manage'] and len(r['cities']) == 2  # isolated from admin's empty list
        assert client.put('/api/v1/weather/cities',headers=headers,json={'cities':[]}).status_code == 403
        with main.db() as c:
            c.execute("INSERT INTO role_page_permissions(role,page,access) VALUES('readonly','weather','none')")
        assert client.get('/api/v1/weather/cities').status_code == 403


def test_weather_size_and_coordinate_limits():
    with pytest.raises(ValidationError):
        weather.CitiesInput(cities=weather.DEFAULT_CITIES*13)
    with pytest.raises(ValidationError):
        weather.City(**{**weather.DEFAULT_CITIES[0],'lat':float('inf')})


def test_dropdown_theme_covers_native_options():
    css=(main.BASE_DIR/'app/assets/visual/theme.css').read_text()
    assert 'html[data-theme="dark"] :is(option,optgroup)' in css
    assert 'background-color:#102338!important;color:#edf5ff!important' in css
    assert 'color-scheme:dark!important' in css
