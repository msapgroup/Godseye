"""Persistent, explicit device identities; IP addresses are never identity keys."""
import json
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
    c.execute('''CREATE TABLE IF NOT EXISTS device_saved_names (
        mac TEXT PRIMARY KEY, fields_json TEXT NOT NULL, updated_at TEXT NOT NULL
    )''')
    # Friendly names have always been entered by a user. Recover hostname
    # edit markers from older releases' audit records when available.
    c.execute('''INSERT OR IGNORE INTO device_saved_fields
        SELECT id,'name',last_seen FROM devices WHERE name IS NOT NULL AND name<>'' ''')
    if c.execute("SELECT 1 FROM sqlite_master WHERE name='audit_log'").fetchone():
        c.execute('''INSERT OR IGNORE INTO device_saved_fields
            SELECT d.id,'hostname',a.created_at FROM devices d JOIN audit_log a ON a.target=d.mac
            WHERE a.action='device_updated' AND instr(a.details,'hostname=?')>0
            ORDER BY a.id DESC''')
    # Upgrade existing manual edits without asking users to re-enter names.
    # Never refresh a saved value from later discovery data.
    legacy = c.execute('''SELECT d.mac,d.name,d.hostname,s.field,s.updated_at
        FROM devices d JOIN device_saved_fields s ON s.device_id=d.id
        WHERE s.field IN ('name','hostname')''').fetchall()
    profiles = saved_names(c)
    for row in legacy:
        key = normalize_mac(row['mac']) or row['mac']
        if row['field'] not in profiles.get(key, {}):
            values = profiles.setdefault(key, {})
            values[row['field']] = row[row['field']]
            c.execute('INSERT OR REPLACE INTO device_saved_names VALUES(?,?,?)',
                      (key, json.dumps(values), row['updated_at']))


def saved_names(c):
    if not c.execute("SELECT 1 FROM sqlite_master WHERE name='device_saved_names'").fetchone():
        return {}
    result = {}
    for row in c.execute('SELECT mac,fields_json FROM device_saved_names'):
        try:
            values = json.loads(row['fields_json'])
        except (TypeError, ValueError):
            continue
        if isinstance(values, dict):
            result[row['mac']] = {k: v for k, v in values.items()
                                  if k in ('name', 'hostname') and isinstance(v, str)}
    return result


def save_names(c, mac, fields, timestamp):
    values = {k: v for k, v in fields.items() if k in ('name', 'hostname') and isinstance(v, str)}
    if not values:
        return
    key = normalize_mac(mac) or mac
    previous = saved_names(c).get(key, {})
    previous.update(values)
    c.execute('INSERT OR REPLACE INTO device_saved_names VALUES(?,?,?)',
              (key, json.dumps(previous), timestamp))


def named_device(c, row, profiles=None):
    """Read saved manual values without acquiring a write lock during polling."""
    data = dict(row)
    profiles = saved_names(c) if profiles is None else profiles
    data.update(profiles.get(normalize_mac(data['mac']) or data['mac'], {}))
    return data


def restore_names(c, device_id=None):
    """Reapply manual names if a discovery record was refreshed or recreated."""
    profiles = saved_names(c)
    if not profiles:
        return
    query = 'SELECT id,mac,name,hostname FROM devices'
    rows = c.execute(query if device_id is None else query + ' WHERE id=?',
                     () if device_id is None else (device_id,)).fetchall()
    for row in rows:
        values = profiles.get(normalize_mac(row['mac']) or row['mac'], {})
        changes = {k: v for k, v in values.items() if row[k] != v}
        if changes:
            columns = ','.join(k + '=?' for k in changes)
            c.execute(f'UPDATE devices SET {columns} WHERE id=?', (*changes.values(), row['id']))


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


def has_saved_identity(c, row):
    data = dict(row)
    if (data.get('name') or data.get('device_type') or data.get('notes') or data.get('icon_data')
            or data.get('icon_key', 'auto') != 'auto' or data.get('trusted')
            or data.get('classification', 'new') not in ('new', None)
            or saved_names(c).get(normalize_mac(data['mac']) or data['mac'])):
        return True
    return (c.execute("SELECT 1 FROM sqlite_master WHERE name='device_saved_fields'").fetchone()
            and c.execute('SELECT 1 FROM device_saved_fields WHERE device_id=?', (data['id'],)).fetchone()) is not None


def match_discovery(c, mac, ip):
    """MAC first; a saved offline identity can reconnect at its last IP.

    Never replace a separately customized device or guess between multiple
    saved offline identities at the same address.
    """
    current = find_device(c, mac)
    if current and has_saved_identity(c, current):
        return current
    candidates = [r for r in c.execute("SELECT * FROM devices WHERE ip=? AND status='offline'", (ip,))
                  if has_saved_identity(c, r)] if ip else []
    if len(candidates) == 1 and (not current or current['id'] != candidates[0]['id']):
        return candidates[0]
    return current


def remember_address(c, device_id, mac, timestamp):
    """An administrator explicitly identifies a changed/private address.

    Only an uncustomized discovery row may be consolidated automatically.
    Retain the remembered row's ID, all edits and its first-seen timestamp.
    """
    ensure_schema(c)
    restore_names(c)
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
                or saved_names(c).get(normalize_mac(source['mac']) or source['mac'])
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
