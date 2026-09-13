import sqlite3
from app.intelligence import ensure_schema
from app.discovery_intelligence import ingest_observations, build_live_topology, normalize_mac


def _db():
    c=sqlite3.connect(':memory:')
    c.row_factory=sqlite3.Row
    c.execute('''CREATE TABLE devices(id INTEGER PRIMARY KEY,mac TEXT UNIQUE,ip TEXT,hostname TEXT,vendor TEXT,name TEXT,device_type TEXT,status TEXT,first_seen TEXT,last_seen TEXT,classification TEXT,missed_scans INTEGER)''')
    c.execute('''CREATE TABLE events(id INTEGER PRIMARY KEY,mac TEXT,event_type TEXT,ip TEXT,created_at TEXT,details TEXT,severity TEXT)''')
    ensure_schema(c)
    return c


def test_normalize_mac():
    assert normalize_mac('AA-BB-CC-DD-EE-FF') == 'aa:bb:cc:dd:ee:ff'


def test_multisource_correlation_and_topology():
    c=_db()
    ingest_observations(c,'dhcp',[{'mac':'AA:BB:CC:DD:EE:FF','ip':'192.168.1.20','hostname':'living-room'}],gateway='192.168.1.1')
    ingest_observations(c,'unifi',[{'mac':'aa:bb:cc:dd:ee:ff','ip':'192.168.1.20','access_point_id':'11:22:33:44:55:66','ssid':'Home'}],gateway='192.168.1.1')
    d=c.execute('select * from devices').fetchone()
    assert d['hostname']=='living-room'
    sources={r['source'] for r in c.execute('select * from device_sources')}
    assert {'dhcp','unifi'} <= sources
    links=[dict(r) for r in c.execute('select * from topology_links')]
    assert any(x['link_type']=='wifi_client' for x in links)
    topo=build_live_topology(c)
    assert any(n.get('mac')=='aa:bb:cc:dd:ee:ff' for n in topo['nodes'])
    assert any(l['link_type']=='wifi_client' for l in topo['links'])
