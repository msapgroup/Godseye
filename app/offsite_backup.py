"""Portable scheduled backups to a network share or attached disk."""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import zipfile

AUTO_MOUNT_ROOT=Path('/var/lib/godseye-local-backup')
AUTO_BACKUP_PATH=AUTO_MOUNT_ROOT/'.godseye-backups'
MOUNT_HELPER='/usr/local/sbin/godseye-mount-backup'


def mount_local_disk(uuid):
    if not re.fullmatch(r'[A-Za-z0-9-]{1,128}',uuid or ''):
        raise ValueError('Invalid disk UUID')
    try:
        result=subprocess.run(['sudo','-n',MOUNT_HELPER,uuid],capture_output=True,text=True,timeout=30,check=False)
    except (OSError,subprocess.SubprocessError) as exc:
        raise RuntimeError('Automatic disk mounting is unavailable. Reinstall the GODSEYE server update.') from exc
    if result.returncode:
        raise RuntimeError('Could not mount the disk: '+(result.stderr.strip() or 'mount helper failed')[:300])
    if result.stdout.strip()!=str(AUTO_BACKUP_PATH):raise RuntimeError('Mount helper returned an unexpected path')
    return str(AUTO_BACKUP_PATH)


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ensure_schema(c):
    c.execute('''CREATE TABLE IF NOT EXISTS portable_backup_settings(
        id INTEGER PRIMARY KEY CHECK(id=1), reminders_enabled INTEGER NOT NULL DEFAULT 1,
        reminder_days INTEGER NOT NULL DEFAULT 7, last_download_at TEXT,
        enabled INTEGER NOT NULL DEFAULT 0, share_path TEXT NOT NULL DEFAULT '',
        hour_utc INTEGER NOT NULL DEFAULT 2, keep_count INTEGER NOT NULL DEFAULT 30,
        last_success_at TEXT, last_attempt_at TEXT, last_error TEXT NOT NULL DEFAULT '',
        instance_token TEXT NOT NULL DEFAULT '')''')
    if not c.execute('SELECT 1 FROM portable_backup_settings WHERE id=1').fetchone():
        c.execute('INSERT OR IGNORE INTO portable_backup_settings(id,instance_token) VALUES(1,?)',(secrets.token_hex(8),))
    c.execute('''CREATE TABLE IF NOT EXISTS portable_backup_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
        filename TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')''')
    c.execute('''CREATE TABLE IF NOT EXISTS local_backup_settings(
        id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0,
        share_path TEXT NOT NULL DEFAULT '', hour_utc INTEGER NOT NULL DEFAULT 2,
        keep_count INTEGER NOT NULL DEFAULT 30, last_success_at TEXT,
        last_attempt_at TEXT, last_error TEXT NOT NULL DEFAULT '',
        instance_token TEXT NOT NULL DEFAULT '', volume_uuid TEXT NOT NULL DEFAULT '')''')
    if not c.execute('SELECT 1 FROM local_backup_settings WHERE id=1').fetchone():
        c.execute('INSERT OR IGNORE INTO local_backup_settings(id,instance_token) VALUES(1,?)',(secrets.token_hex(8),))
    c.execute('''CREATE TABLE IF NOT EXISTS local_backup_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
        filename TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')''')


def settings(c):
    ensure_schema(c)
    return dict(c.execute('SELECT * FROM portable_backup_settings WHERE id=1').fetchone())


def local_settings(c):
    ensure_schema(c)
    return dict(c.execute('SELECT * FROM local_backup_settings WHERE id=1').fetchone())


def validate_share(path):
    path=Path(path)
    if not path.is_absolute() or not path.is_dir():
        raise ValueError('Enter an existing absolute path to a mounted SMB share')
    # The path itself must be the mount point, so a disconnected share cannot
    # silently write sensitive backups into the local mountpoint directory.
    if not os.path.ismount(path):
        raise ValueError('The selected path is not a mounted network share')
    result=subprocess.run(['findmnt','-n','-o','FSTYPE','--mountpoint',str(path)],capture_output=True,text=True,timeout=5,check=False)
    if result.returncode or result.stdout.strip().lower() not in ('cifs','smb3'):
        raise ValueError('The selected mount must be an SMB/CIFS network share')
    return path


def test_share(path):
    directory=validate_share(path)
    fd,name=tempfile.mkstemp(prefix='.godseye-write-test-',dir=directory)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(b'GODSEYE backup connection test'); f.flush(); os.fsync(f.fileno())
    finally:
        Path(name).unlink(missing_ok=True)


def validate_local_disk(path, db_path, expected_uuid=''):
    path=Path(path)
    auto=path==AUTO_BACKUP_PATH
    mountpoint=AUTO_MOUNT_ROOT if auto else path
    if not path.is_absolute() or not path.is_dir() or not os.path.ismount(mountpoint) or (auto and path.is_symlink()):
        raise ValueError('Enter the mount point of an attached local disk')
    result=subprocess.run(['findmnt','-n','-r','-o','FSTYPE,SOURCE,UUID','--mountpoint',str(mountpoint)],capture_output=True,text=True,timeout=5,check=False)
    fields=result.stdout.strip().split()
    local_filesystems={'ext2','ext3','ext4','xfs','btrfs','vfat','exfat','ntfs','ntfs3','fuseblk'}
    if result.returncode or len(fields)!=3 or fields[0].lower() not in local_filesystems or not fields[1].startswith('/dev/') or fields[2]=='-':
        raise ValueError('The destination must be a mounted local disk with a filesystem UUID')
    if os.stat(path).st_dev==os.stat(Path(db_path).parent).st_dev:
        raise ValueError('The backup disk must be separate from the GODSEYE data filesystem')
    if expected_uuid and fields[2]!=expected_uuid:
        raise ValueError('The mounted disk is not the disk saved in backup settings')
    return path,fields[2]


def discover_local_disks(db_path):
    """List local filesystems without mounting or modifying any device."""
    try:
        result=subprocess.run(['lsblk','--json','--bytes','--paths','--output',
                               'NAME,TYPE,FSTYPE,UUID,LABEL,MOUNTPOINTS,SIZE,RO'],
                              capture_output=True,text=True,timeout=8,check=False)
    except (OSError,subprocess.SubprocessError) as exc:
        raise RuntimeError('Unable to scan attached disks: '+str(exc)) from exc
    if result.returncode:
        raise RuntimeError('Unable to scan attached disks: '+(result.stderr.strip() or 'lsblk failed')[:200])
    try: devices=json.loads(result.stdout)['blockdevices']
    except (ValueError,KeyError,TypeError) as exc:raise RuntimeError('Unable to read disk information') from exc
    supported={'ext2','ext3','ext4','xfs','btrfs','vfat','exfat','ntfs','ntfs3','fuseblk'}
    disks=[]
    def visit(nodes):
        for node in nodes:
            children=node.get('children') or []
            if children:visit(children)
            fs=str(node.get('fstype') or '').lower()
            name=str(node.get('name') or '')
            uuid=str(node.get('uuid') or '')
            if fs not in supported or not name.startswith('/dev/') or not uuid:continue
            mounts=[m for m in (node.get('mountpoints') or []) if isinstance(m,str) and m]
            # Bound the amount of work on hosts with unusually large block lists.
            for path in (mounts or [''])[:8]:
                if len(disks)>=100:return
                auto_mount=not path and not node.get('ro')
                ready=auto_mount;reason='Ready to mount automatically' if auto_mount else 'Disk is read-only'
                if path==str(AUTO_MOUNT_ROOT):path=str(AUTO_BACKUP_PATH)
                if path:
                    try:
                        validate_local_disk(path,db_path)
                        if node.get('ro'):
                            reason='Disk is read-only'
                        elif not os.access(path,os.W_OK):
                            reason='GODSEYE cannot write to this mount'
                        else:
                            ready=True;reason='Ready'
                    except (OSError,ValueError,subprocess.SubprocessError) as exc:
                        reason=str(exc)
                        if 'same' in reason or 'separate' in reason:continue
                disks.append({'device':name,'label':str(node.get('label') or ''),
                              'uuid':uuid,'mountpoint':path,'size_bytes':node.get('size'),
                              'ready':ready,'reason':reason,'auto_mount':auto_mount})
    visit(devices)
    return disks


def test_local_disk(path, db_path, expected_uuid=''):
    directory,uuid=validate_local_disk(path,db_path,expected_uuid)
    fd,name=tempfile.mkstemp(prefix='.godseye-write-test-',dir=directory)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(b'GODSEYE backup connection test');f.flush();os.fsync(f.fileno())
    finally:
        Path(name).unlink(missing_ok=True)
    return uuid


def create_bundle(db_path, key_path, destination, config):
    """Write a restorable bundle to a temporary local file and verify integrity."""
    key=Path(key_path).read_bytes()
    if not key:
        raise ValueError('Appliance encryption key is missing')
    fd,db_name=tempfile.mkstemp(prefix='godseye-snapshot-',suffix='.db',dir=Path(db_path).parent)
    os.close(fd)
    try:
        os.chmod(db_name,0o600)
        with sqlite3.connect(str(db_path)) as source, sqlite3.connect(db_name) as snapshot:
            source.backup(snapshot)
            if snapshot.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise RuntimeError('Backup database integrity check failed')
        if Path(db_name).stat().st_size > 256*1024*1024:
            raise ValueError('Database exceeds the 256 MB portable restore limit')
        digest=hashlib.sha256()
        with open(db_name,'rb') as f:
            for block in iter(lambda:f.read(1024*1024),b''): digest.update(block)
        manifest={'format':'godseye-full-backup','version':1,'created_at':utcnow(),
                  'database_sha256':digest.hexdigest(),'key_sha256':hashlib.sha256(key).hexdigest()}
        with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=4) as z:
            z.write(db_name,'database.db');z.writestr('secret.key',key)
            z.writestr('settings.json',json.dumps(config,indent=2));z.writestr('manifest.json',json.dumps(manifest,indent=2))
        os.chmod(destination,0o600)
        if Path(destination).stat().st_size > 256*1024*1024:
            raise ValueError('Backup exceeds the 256 MB portable restore limit')
        with zipfile.ZipFile(destination) as z:
            if z.testzip() is not None: raise RuntimeError('Backup archive verification failed')
    finally:
        Path(db_name).unlink(missing_ok=True)


class OffsiteBackupManager:
    def __init__(self,db_factory,db_path,key_path,config_export,local=False):
        self.db_factory=db_factory; self.db_path=db_path; self.key_path=key_path; self.config_export=config_export
        self.local=local;self.table='local_backup_settings' if local else 'portable_backup_settings';self.history='local_backup_history' if local else 'portable_backup_history'
        self.stop_event=threading.Event(); self.thread=None; self.lock=threading.Lock()
    def start(self):
        if self.thread and self.thread.is_alive(): return
        self.thread=threading.Thread(target=self._loop,name='godseye-offsite-backup',daemon=True);self.thread.start()
    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=3)
    def _loop(self):
        while not self.stop_event.wait(60):
            try:self.run_if_due()
            except Exception as exc:print('[GODSEYE] offsite backup:',exc)
    def run_if_due(self):
        now=dt.datetime.now(dt.timezone.utc)
        with self.db_factory() as c: cfg=local_settings(c) if self.local else settings(c)
        last=cfg['last_success_at'] or ''
        attempt=cfg['last_attempt_at'] or ''
        if not cfg['enabled'] or now.hour<int(cfg['hour_utc']) or last[:10]==now.date().isoformat():return
        # Retrying every hour limits load and records persistent failures.
        if attempt:
            try:
                if (now-dt.datetime.fromisoformat(attempt)).total_seconds()<3600:return
            except ValueError:pass
        self.run()
    def run(self):
        if not self.lock.acquire(blocking=False):raise RuntimeError('A backup to this destination is already running')
        local_name=None; partial=None
        try:
            with self.db_factory() as c:
                cfg=local_settings(c) if self.local else settings(c); c.execute(f"UPDATE {self.table} SET last_attempt_at=? WHERE id=1",(utcnow(),))
            if self.local:
                if not cfg['volume_uuid']:raise ValueError('The backup disk identity is not configured')
                if cfg['share_path']==str(AUTO_BACKUP_PATH) and not os.path.ismount(AUTO_MOUNT_ROOT):
                    mount_local_disk(cfg['volume_uuid'])
                share,_=validate_local_disk(cfg['share_path'],self.db_path,cfg['volume_uuid'])
            else:share=validate_share(cfg['share_path'])
            with self.db_factory() as c: config=self.config_export(c)
            fd,local_name=tempfile.mkstemp(prefix='godseye-portable-',suffix='.zip',dir=Path(self.db_path).parent);os.close(fd)
            create_bundle(self.db_path,self.key_path,local_name,config)
            filename='godseye-full-'+cfg['instance_token']+'-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.zip'
            # A temporary name and atomic rename avoid advertising incomplete files.
            fd,partial=tempfile.mkstemp(prefix='.godseye-partial-',dir=share)
            with os.fdopen(fd,'wb') as out,open(local_name,'rb') as source:
                while True:
                    block=source.read(1024*1024)
                    if not block:break
                    out.write(block)
                out.flush();os.fsync(out.fileno())
            with open(local_name,'rb') as a,open(partial,'rb') as b:
                while True:
                    x=a.read(1024*1024);y=b.read(1024*1024)
                    if x!=y:raise RuntimeError('Backup destination verification failed')
                    if not x:break
            os.replace(partial,share/filename);partial=None
            with self.db_factory() as c:
                c.execute(f"UPDATE {self.table} SET last_success_at=?,last_error='' WHERE id=1",(utcnow(),))
                c.execute(f"INSERT INTO {self.history}(created_at,filename,status) VALUES(?,?,'complete')",(utcnow(),filename))
            files=sorted(share.glob('godseye-full-'+cfg['instance_token']+'-????????T????????????Z.zip'),reverse=True)
            for old in files[int(cfg['keep_count']):]:old.unlink()
            return {'ok':True,'filename':filename}
        except Exception as exc:
            with self.db_factory() as c:
                c.execute(f'UPDATE {self.table} SET last_error=? WHERE id=1',(str(exc)[:500],))
                c.execute(f"INSERT INTO {self.history}(created_at,status,detail) VALUES(?,'failed',?)",(utcnow(),str(exc)[:500]))
            raise
        finally:
            if partial:Path(partial).unlink(missing_ok=True)
            if local_name:Path(local_name).unlink(missing_ok=True)
            self.lock.release()
