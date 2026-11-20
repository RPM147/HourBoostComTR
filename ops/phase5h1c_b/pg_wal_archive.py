"""Durable candidate archive enrollment and read-only warning policy. Linux, no pruning."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

NAME = 'wal-archive'
INNER = '/run/hourboost-wal'
PUBLISH_SHA = 'dcee432127755f01e9e44ddd52a59c5fc76ec9992638ef3a20b73a54e8e8c594'
GIB = 1024**3
QUERY = """SELECT count(*)::text || '|' ||
    COALESCE(GREATEST(0, EXTRACT(EPOCH FROM now()-min(modification)))::bigint,0)::text || '|' ||
    (SELECT CASE WHEN last_failed_time IS NOT NULL AND
                      (last_archived_time IS NULL OR last_failed_time > last_archived_time)
                 THEN 1 ELSE 0 END FROM pg_catalog.pg_stat_archiver)::text
    FROM pg_catalog.pg_ls_archive_statusdir() WHERE right(name,6)='.ready'"""


def need(test, gate):
    if not test:
        raise RuntimeError(gate)


def fsync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def marker(b, g, folder, system_id):
    root = b.owned_dir(g, folder)
    wal = b.owned_dir(g, folder / 'wal', 999)
    cluster = json.loads(g.root_file(g.TARGET / 'owner.json', mode=0o600, limit=2048))
    return dict(schema='hourboost-wal-archive-v1', system_id=system_id, generation=cluster['generation'],
                volume=g.VOLUME_UUID, filesystem=g.FILESYSTEM_UUID, directory=root.st_ino, wal=wal.st_ino)


def validate(b, g, system_id):
    folder = g.TARGET / NAME
    expected = marker(b, g, folder, system_id)
    need({p.name for p in folder.iterdir()} == {'identity.json', 'wal'}, 'archive-layout')
    need(json.loads(g.root_file(folder/'identity.json', mode=0o600, limit=2048)) == expected,
         'archive-identity')
    return folder / 'wal'


def prepare(b, g, system_id):
    # Called only while the verified volume locks are held and the existing candidate is idle.
    final, stage = g.TARGET / NAME, g.TARGET / '.wal-archive-preparing'
    if os.path.lexists(final):
        return validate(b, g, system_id)
    stage.mkdir(mode=0o700)  # O_EXCL semantics for this directory: never adopt interrupted work.
    wal = stage / 'wal'
    wal.mkdir(mode=0o700)
    os.chown(wal, 999, 999, follow_symlinks=False)
    with (stage/'identity.json').open('xb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps(marker(b,g,stage,system_id), sort_keys=True).encode('ascii')+b'\n')
        f.flush()
        os.fsync(f.fileno())
    fsync_dir(wal); fsync_dir(stage)
    os.rename(stage, final)
    fsync_dir(g.TARGET)
    return validate(b, g, system_id)


def publisher(g):
    source = g.root_file(g.INSTALL/'pg_wal_publish.sh', mode=0o700, limit=8192)
    need(hashlib.sha256(source).hexdigest() == PUBLISH_SHA, 'archive-publisher-drift')
    return source.decode('ascii')


def levels(free, pending, age, failed):
    codes = []
    if free <= 24*GIB: codes.append('disk-critical')
    elif free <= 26*GIB: codes.append('disk-warning')
    if pending and age >= 900: codes.append('wal-lag-critical')
    elif pending and age >= 300: codes.append('wal-lag-warning')
    if failed: codes.append('archiver-failure')
    return codes


def health(b, g, cid, socket):
    statv = os.statvfs(g.MOUNT)
    free = statv.f_bavail * statv.f_frsize
    result = b.docker('exec', '--user=999:999', cid, 'psql', '-XqAtw', '-v', 'ON_ERROR_STOP=1',
                      '-h', socket, '-U', 'postgres', '-d', 'hourboost', '-c', QUERY, timeout=6)
    match = re.fullmatch(rb'(\d{1,12})\|(\d{1,12})\|([01])\n', result.stdout)
    need(match is not None, 'archive-status-invalid')
    pending, age, failed = map(int, match.groups())
    return dict(volume_free_bytes=free, pending=pending, oldest_ready_seconds=age,
                last_attempt_failed=bool(failed), alerts=levels(free,pending,age,failed))


class Monitor:
    """Sample during the existing supervisor loop; monitoring errors never stop the database."""
    def __init__(self):
        self.next_check, self.last_report, self.last = 0, 0, None

    def tick(self, b, g, cid, socket):
        now = time.monotonic()
        if now < self.next_check:
            return
        self.next_check = now + 30
        try:
            alerts = tuple(health(b,g,cid,socket)['alerts'])
        except Exception:
            alerts = ('monitor-unavailable',)
        if alerts != self.last or (alerts and now-self.last_report >= 900):
            print(('<4>' if alerts else '<6>')+'hourboost-wal: '+(','.join(alerts) or 'ok'),
                  file=sys.stderr, flush=True)
            self.last_report, self.last = now, alerts
