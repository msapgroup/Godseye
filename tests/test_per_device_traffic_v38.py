import sqlite3
from pathlib import Path

def _db(path):
    c=sqlite3.connect(path)
    c.row_factory=sqlite3.Row
    return c

def test_normalized_delta_and_cumulative_ingestion(tmp_path):
    from app.traffic_intelligence import ensure_schema, ingest_samples, device_usage
    c=_db(tmp_path/"traffic.db")
    c.execute("""CREATE TABLE devices(
      id INTEGER PRIMARY KEY, name TEXT, hostname TEXT, mac TEXT, ip TEXT, last_seen TEXT
    )""")
    c.execute("INSERT INTO devices(id,name,mac,ip,last_seen) VALUES(1,'Laptop','aa:bb:cc:dd:ee:ff','192.168.1.20','x')")
    ensure_schema(c)
    ingest_samples(c,"span",[{"mac":"aa:bb:cc:dd:ee:ff","rx_bytes":1000,"tx_bytes":500,"interval_seconds":10}],source_ref="eth1",counter_mode="delta")
    usage=device_usage(c,24)
    assert usage["devices"][0]["rx_bytes"]==1000
    assert usage["devices"][0]["tx_bytes"]==500
    assert usage["devices"][0]["peak_rx_bps"]==800
    c.close()

def test_cumulative_counters_derive_positive_deltas(tmp_path):
    from app.traffic_intelligence import ensure_schema, ingest_samples
    c=_db(tmp_path/"counters.db")
    c.execute("CREATE TABLE devices(id INTEGER PRIMARY KEY,name TEXT,hostname TEXT,mac TEXT,ip TEXT,last_seen TEXT)")
    c.execute("INSERT INTO devices VALUES(1,'Phone','','11:22:33:44:55:66','192.168.1.30','x')")
    ensure_schema(c)
    ingest_samples(c,"unifi",[{"mac":"11:22:33:44:55:66","rx_bytes":10000,"tx_bytes":4000}],source_ref="7",captured_at="2026-09-12T10:00:00+00:00")
    ingest_samples(c,"unifi",[{"mac":"11:22:33:44:55:66","rx_bytes":16000,"tx_bytes":7000}],source_ref="7",captured_at="2026-09-12T10:01:00+00:00")
    row=c.execute("SELECT * FROM device_traffic_samples ORDER BY id DESC LIMIT 1").fetchone()
    assert row["rx_delta_bytes"]==6000 and row["tx_delta_bytes"]==3000
    assert round(row["rx_bps"])==800 and round(row["tx_bps"])==400
    c.close()

def test_report_uses_per_device_store_not_appliance_totals(tmp_path):
    from app.integration_reporting import ensure_schema as ensure_ir, build_report
    from app.traffic_intelligence import ensure_schema as ensure_ti, ingest_samples
    c=_db(tmp_path/"report.db")
    c.executescript("""
    CREATE TABLE devices(id INTEGER PRIMARY KEY,name TEXT,hostname TEXT,mac TEXT,ip TEXT,last_seen TEXT,status TEXT,classification TEXT,device_type TEXT,vendor TEXT,first_seen TEXT);
    CREATE TABLE network_issues(id INTEGER PRIMARY KEY,severity TEXT,issue_type TEXT,target TEXT,title TEXT,status TEXT,first_seen TEXT,last_seen TEXT,recommendation TEXT);
    CREATE TABLE integration_checks(id INTEGER PRIMARY KEY,status TEXT);
    CREATE TABLE integration_settings(id INTEGER PRIMARY KEY,name TEXT,kind TEXT,target TEXT,enabled INTEGER,interval_seconds INTEGER);
    CREATE TABLE events(id INTEGER PRIMARY KEY,created_at TEXT,event_type TEXT,mac TEXT,ip TEXT,details TEXT);
    CREATE TABLE topology_links(id INTEGER PRIMARY KEY,parent TEXT,child TEXT,link_type TEXT,details TEXT,last_seen TEXT,UNIQUE(parent,child,link_type));
    """)
    c.execute("INSERT INTO devices VALUES(1,'Desktop','','aa:aa:aa:aa:aa:aa','10.0.0.8','x','online','known','PC','Vendor','x')")
    ensure_ir(c); ensure_ti(c)
    c.execute("UPDATE traffic_collection_settings SET enabled=1,mode='span',interface='eth1',last_status='success' WHERE id=1")
    ingest_samples(c,"span",[{"mac":"aa:aa:aa:aa:aa:aa","rx_bytes":2000,"tx_bytes":1000,"interval_seconds":10}],source_ref="eth1",counter_mode="delta")
    summary,body=build_report(c,"traffic_usage")
    assert summary["devices_with_traffic"]==1
    assert summary["download_bytes_24h"]==2000
    assert "Per-Device Traffic Usage" in body
    assert "appliance-interface traffic" not in body
    c.close()

def test_reports_ui_has_explicit_source_modes():
    from app import main
    html=main.DASHBOARD
    assert 'id="trafficMode"' in html
    assert '>UniFi / Controller<' in html
    assert '>SNMP<' in html
    assert '>SPAN / Mirror<' in html
    assert '>Inline / Gateway<' in html
    assert 'id="trafficDeviceRows"' in html
    assert '/api/v1/traffic/config' in html
    assert '/api/v1/traffic/collect-now' in html

def test_v38_version():
    assert Path("VERSION").read_text().strip().startswith(("3.8.0-","3.9.0-", "4.0.0-", "4.1.0-", "4.2.0-", "4.3.0-", "4.4.0-", "4.5.0-", "4.6.0-", "4.7.0-"))


def _login_admin(main, client):
    password="Godseye-Test-2026!Strong"
    assert client.post("/api/v1/auth/setup",json={"current_password":"","new_password":password}).status_code==200
    assert client.post("/api/v1/auth/login",json={"username":"admin","password":password}).status_code==200
    return {"X-CSRF-Token":client.cookies.get("godseye_csrf")}

def test_traffic_config_and_ingest_api(tmp_path):
    from app import main
    from fastapi.testclient import TestClient
    old=main.DB_PATH
    main.DB_PATH=tmp_path/"api.db"
    try:
        main.init_db()
        with TestClient(main.app) as client:
            headers=_login_admin(main,client)
            cfg=client.get("/api/v1/traffic/config").json()
            assert set(cfg["modes"])=={"unifi","snmp","span","inline"}
            interfaces=cfg["interfaces"]
            if interfaces:
                saved=client.put("/api/v1/traffic/config",headers=headers,json={
                    "enabled":True,"mode":"span","interface":interfaces[0],
                    "integration_id":None,"sample_interval_seconds":30,"options":{}
                })
                assert saved.status_code==200,saved.text
                ing=client.post("/api/v1/traffic/ingest",headers=headers,json={
                    "mode":"span","source_ref":interfaces[0],"counter_mode":"delta",
                    "samples":[{"mac":"aa:bb:cc:11:22:33","ip":"10.0.0.50","rx_bytes":4096,"tx_bytes":2048,"interval_seconds":10}]
                })
                assert ing.status_code==200,ing.text
                assert ing.json()["samples_ingested"]==1
                usage=client.get("/api/v1/traffic/devices?hours=24").json()
                assert usage["total_rx_bytes"]==4096
    finally:
        main.DB_PATH=old
