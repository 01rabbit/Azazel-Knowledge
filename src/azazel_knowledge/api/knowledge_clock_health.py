"""Local lab clock health. BOOTTIME values never cross node boundaries."""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat
import time
from threading import Lock
from azazel_fabric.knowledge_context_clocklab import ClockContract

_FIELDS = {"schema", "boot_id", "sample_boottime_ns", "sample_wall_ns",
           "error_bound_us", "step_counter", "contract_id"}

class LocalClockHealth:
    def __init__(self, path: str, *, boottime=None, wall=None, boot_id=None):
        self.path = path
        self._boottime = boottime or (lambda: time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        self._wall = wall or time.time_ns
        self._boot_id = boot_id or (lambda: Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        self._generation = None
        self._last_wall = None
        self._failed = False
        self._lock = Lock()

    def _read(self) -> dict:
        parts = Path(self.path).parts
        if not parts or parts[0] != '/' or '..' in parts or '.' in parts:
            raise ValueError('clock health path invalid')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in parts[1:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = nxt
                st = os.fstat(fd)
                if st.st_uid != 0 or st.st_mode & 0o022:
                    raise ValueError('clock health parent unsafe')
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                st = os.fstat(leaf)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1:
                    raise ValueError('clock health file unsafe')
                raw = os.read(leaf, 4097)
                if len(raw) > 4096: raise ValueError('clock health too large')
                def pairs(items):
                    out = {}
                    for key,value in items:
                        if key in out: raise ValueError('clock health duplicate key')
                        out[key]=value
                    return out
                return json.loads(raw, object_pairs_hook=pairs)
            finally: os.close(leaf)
        finally: os.close(fd)

    def check(self, contract: ClockContract) -> None:
        with self._lock:
            if self._failed: raise ValueError('clock health latched invalid')
            try:
                self._check(contract)
            except Exception:
                self._failed = True
                raise

    def _check(self, contract: ClockContract) -> None:
        if type(contract) is not ClockContract: raise ValueError('clock policy invalid')
        d = self._read()
        if type(d) is not dict or set(d) != _FIELDS or d['schema'] != 'azazel-clocklab-health/1':
            raise ValueError('clock health malformed')
        for key in ('sample_boottime_ns', 'sample_wall_ns', 'error_bound_us', 'step_counter'):
            if type(d[key]) is not int or d[key] < 0: raise ValueError('clock health number invalid')
        if d['boot_id'] != self._boot_id() or d['contract_id'] != contract.contract_id:
            raise ValueError('clock health binding invalid')
        now_mono, now_wall = self._boottime(), self._wall()
        age = now_mono - d['sample_boottime_ns']
        if not 0 <= age < contract.max_observation_age_ms * 1_000_000:
            raise ValueError('clock health expired')
        if d['error_bound_us'] > 1000:
            raise ValueError('clock health error budget exceeded')
        # 100ppm is an explicit lab hypothesis, never a production guarantee.
        residual = abs(now_wall - d['sample_wall_ns'] - age)
        if residual > 2_000_000 + age // 10_000:
            raise ValueError('clock health step detected')
        generation = (d['boot_id'], d['step_counter'])
        if self._generation is not None and self._generation != generation:
            raise ValueError('clock health generation changed')
        if self._last_wall is not None and now_wall < self._last_wall:
            raise ValueError('clock health rollback detected')
        self._generation, self._last_wall = generation, now_wall
