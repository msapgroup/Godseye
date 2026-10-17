"""Persistent, explicit device identities; IP addresses are never identity keys."""
from .enrichment import normalize_mac


def ensure_schema(c):
    c.execute("""CREATE TABLE IF NOT EXISTS device_mac_aliases (
        mac TEXT PRIMARY KEY, device_id INTEGER NOT NULL, created_at TEXT NOT NULL
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_device_alias_owner ON device_mac_aliases(device_id)")
    c.execute('''CREATE TABLE IF NOT EXISTS device_saved_fields (
        device_id INTEGER NOT NULL, field TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY(device_id,field)
    )''')


def field_is_saved(c, device_id, field):
    if not c.execute("SELECT 1 FROM sqlite_master WHERE name='device_saved_fields'").fetchone():
        return False
    return c.execute('SELECT 1 FROM device_saved_fields WHERE device_id=? AND field=?',
                     (device_id, field)).fetchone() is not None


def find_device(c, mac):
    normalized = normalize_mac(mac)
    if not normalized:
        return c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
    exact = c.execute('SELECT * FROM devices WHERE mac=?', (normalized,)).fetchone()
    if exact:
        return exact
    # Also recognize legacy mixed-case, hyphenated and dotted MAC records.
    rows = c.execute("""SELECT * FROM devices
        WHERE lower(replace(replace(replace(mac, ':', ''), '-', ''), '.', ''))=?""",
        (normalized.replace(':', ''),)).fetchall()
    if len(rows) == 1:
        return rows[0]
    if len(rows) > 1:
        # Prefer the observed spelling when legacy duplicates already exist;
        # never merge or discard either record automatically.
        return next((r for r in rows if r['mac'] == mac), rows[0])
    if c.execute("SELECT 1 FROM sqlite_master WHERE name='device_mac_aliases'").fetchone():
        return c.execute("""SELECT d.* FROM devices d JOIN device_mac_aliases a
            ON a.device_id=d.id WHERE a.mac=?""", (normalized,)).fetchone()
    return None


def remember_address(c, device_id, mac, timestamp):
    """An administrator explicitly identifies a changed/private address.

    Only an uncustomized discovery row may be consolidated automatically.
    Retain the remembered row's ID, all edits and its first-seen timestamp.
    """
    ensure_schema(c)
    target = c.execute('SELECT * FROM devices WHERE id=?', (device_id,)).fetchone()
    if target is None:
        raise LookupError('Device not found')
    mac = normalize_mac(mac)
    if not mac or mac in {'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'} or int(mac[:2], 16) & 1:
        raise ValueError('Enter a valid unicast device MAC address')
    owner = c.execute('SELECT device_id FROM device_mac_aliases WHERE mac=?', (mac,)).fetchone()
    if owner and owner['device_id'] != device_id:
        raise ValueError('This address is already remembered by another device')
    source = find_device(c, mac)
    if source and source['id'] != device_id:
        source = dict(source)
        if (source.get('name') or source.get('notes') or source.get('device_type')
                or source.get('icon_data') or source.get('icon_key', 'auto') != 'auto'
                or source.get('classification', 'new') != 'new' or source.get('trusted')
                or c.execute('SELECT 1 FROM device_saved_fields WHERE device_id=?', (source['id'],)).fetchone()
                or c.execute("SELECT 1 FROM audit_log WHERE action='device_updated' AND target=? LIMIT 1", (source['mac'],)).fetchone()):
            raise ValueError('That address belongs to a customized device. Its saved details will not be overwritten.')
        old_mac = source['mac']
        for table, keys in [('device_sources', ['source']), ('device_ip_history', ['ip', 'source'])]:
            for item in c.execute(f'SELECT * FROM {table} WHERE mac=?', (old_mac,)).fetchall():
                columns = [k for k in item.keys() if k != 'id']
                values = [target['mac'] if k == 'mac' else item[k] for k in columns]
                conflict = ','.join(['mac'] + keys)
                c.execute(f"""INSERT INTO {table}({','.join(columns)}) VALUES({','.join('?' for _ in columns)})
                    ON CONFLICT({conflict}) DO UPDATE SET
                    first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen)""", values)
            c.execute(f'DELETE FROM {table} WHERE mac=?', (old_mac,))
        c.execute('UPDATE events SET mac=? WHERE mac=?', (target['mac'], old_mac))
        for link in c.execute('SELECT * FROM topology_links WHERE parent=? OR child=?', (old_mac, old_mac)).fetchall():
            c.execute('INSERT OR IGNORE INTO topology_links(parent,child,link_type,details,last_seen) VALUES(?,?,?,?,?)',
                      (target['mac'] if link['parent'] == old_mac else link['parent'],
                       target['mac'] if link['child'] == old_mac else link['child'],
                       link['link_type'], link['details'], link['last_seen']))
        c.execute('DELETE FROM topology_links WHERE parent=? OR child=?', (old_mac, old_mac))
        c.execute('UPDATE network_issues SET target=? WHERE target=?', (target['mac'], old_mac))
        for table in ('diagnostic_runs', 'device_traffic_samples'):
            if c.execute('SELECT 1 FROM sqlite_master WHERE name=?', (table,)).fetchone():
                c.execute(f'UPDATE {table} SET device_id=?,mac=? WHERE device_id=?',
                          (device_id, target['mac'], source['id']))
        c.execute("UPDATE tickets SET linked_id=? WHERE linked_type='device' AND linked_id=?", (device_id, source['id']))
        c.execute('UPDATE device_mac_aliases SET device_id=? WHERE device_id=?', (device_id, source['id']))
        if source['last_seen'] >= target['last_seen']:
            c.execute('''UPDATE devices SET ip=?,status=?,last_seen=?,missed_scans=?,offline_escalated_at=NULL
                WHERE id=?''', (source['ip'], source['status'], source['last_seen'], source['missed_scans'], device_id))
        c.execute('DELETE FROM devices WHERE id=?', (source['id'],))
        c.execute('DELETE FROM device_saved_fields WHERE device_id=?', (source['id'],))
    c.execute('INSERT OR IGNORE INTO device_mac_aliases(mac,device_id,created_at) VALUES(?,?,?)',
              (mac, device_id, timestamp))
    return target['mac']
