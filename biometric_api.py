from __future__ import annotations
import asyncio
import concurrent.futures
import contextlib
import dataclasses
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

import requests
from pydantic import BaseModel, Field, validator

# ---- CONFIG ------------------------------------------------------------------

class DeviceConfig(BaseModel):
    name: str
    protocol: str = Field(description="e.g. 'zkteco'")
    ip: str
    port: int = 4370
    device_id: str = Field(description="Identifier to store in Employee Checkin.device_id")
    tz: str = "Asia/Kolkata"  # device's local clock timezone
    pull_batch_minutes: int = 24 * 60  # how far back to pull on first run
    options: Dict[str, Any] = Field(default_factory=dict)
    start_from: Optional[str] = None  # format: YYYY-MM-DD

    @validator("start_from")
    def validate_start_from(cls, v):
        """Normalize date format to full ISO with midnight time"""
        if v:
            try:
                # Ensure it's in YYYY-MM-DD
                d = datetime.strptime(v, "%Y-%m-%d")
                return d.strftime("%Y-%m-%dT00:00:00")
            except ValueError:
                raise ValueError("start_from must be in 'YYYY-MM-DD' format (e.g. '2025-01-01')")
        return v


class ERPConfig(BaseModel):
    base_url: str  # e.g. https://your-erp.example.com
    api_key: str
    api_secret: str
    verify_tls: bool = True
    timeout_secs: int = 20
    employee_fieldname: str = "attendance_device_id"  # or custom field
    endpoint: str = (
        "/api/method/hrms.hr.doctype.employee_checkin.employee_checkin.add_log_based_on_employee_field"
    )

class AlertConfig(BaseModel):
    webhook_url: Optional[str] = None  # Slack/Teams/Generic JSON webhook
    min_consecutive_failures: int = 5

class AppConfig(BaseModel):
    timezone_fallback: str = "Asia/Kolkata"
    poll_interval_seconds: int = 60
    max_workers: int = 8  # concurrent devices
    max_push_retries: int = 5
    max_fetch_retries: int = 5
    backoff_base_seconds: float = 1.5
    backoff_max_seconds: float = 60.0
    sqlite_path: str = "./biometric_sync.sqlite"
    log_path: str = "./biometric_sync.log"
    log_level: str = "INFO"
    devices: List[DeviceConfig]
    erp: ERPConfig
    alerting: AlertConfig = AlertConfig()

    @validator("log_level")
    def _lvl(cls, v):
        return v.upper()




# You can load from environment/JSON; for simplicity embed a sane default here:
DEFAULT_CONFIG = AppConfig(
    devices=[
        DeviceConfig(
            name="ABC",
            protocol="zkteco",
            ip="192.168.2.9",
            port=4370,
            device_id="2",
            tz="Asia/Kolkata",
            start_from="2025-10-17",
        ),
        DeviceConfig(
            name="CDE",
            protocol="zkteco",
            ip="192.168.2.9",
            port=4370,
            device_id="3",
            tz="Asia/Kolkata",
            start_from="2025-10-17",
        ),
        DeviceConfig(
            name="FGH",
            protocol="zkteco",
            ip="192.168.2.9",
            port=4370,
            device_id="1",
            tz="Asia/Kolkata",
            start_from="2025-10-17",
        ),
    ],
    erp=ERPConfig(
        base_url="https://erp.company.com/",
        api_key="api_key",
        api_secret="api_secret",
        verify_tls=True,
    ),
)



def load_config() -> AppConfig:
    """
    Option A: set BIOMETRIC_CONFIG_JSON env with the JSON for AppConfig
    Option B: use DEFAULT_CONFIG above
    """
    cfg_json = os.getenv("BIOMETRIC_CONFIG_JSON")
    if cfg_json:
        return AppConfig(**json.loads(cfg_json))
    return DEFAULT_CONFIG

# ---- LOGGING -----------------------------------------------------------------

def setup_logging(cfg: AppConfig) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.log_level, logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    fh = RotatingFileHandler(cfg.log_path, maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)
    root.addHandler(fh)

logger = logging.getLogger("biometric-sync")

# ---- STORAGE (SQLite) --------------------------------------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS checkins (
    hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    ts_utc TEXT NOT NULL,     -- ISO8601 in UTC
    log_type TEXT,            -- IN/OUT or NULL if device doesn't supply
    pushed_at TEXT NOT NULL   -- ISO8601 UTC when pushed to ERP
);

CREATE TABLE IF NOT EXISTS checkpoints (
    device_key TEXT PRIMARY KEY,
    last_ts_utc TEXT NOT NULL  -- last successfully pushed timestamp for device
);

CREATE TABLE IF NOT EXISTS failures (
    name TEXT PRIMARY KEY,
    consecutive INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""

class Store:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.executescript(SCHEMA)
        self._lock = asyncio.Lock()

    async def add_checkin(self, h: str, device_id: str, user_id: str, ts_utc: str, log_type: Optional[str]) -> bool:
        async with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO checkins(hash, device_id, user_id, ts_utc, log_type, pushed_at) VALUES (?,?,?,?,?,?)",
                    (h, device_id, user_id, ts_utc, log_type, datetime.now(timezone.utc).isoformat()),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False  # duplicate

    async def get_checkpoint(self, device_key: str) -> Optional[str]:
        async with self._lock:
            cur = self._conn.execute(
                "SELECT last_ts_utc FROM checkpoints WHERE device_key=?",
                (device_key,),
            )
            row = cur.fetchone()
            return row[0] if row else None

    async def set_checkpoint(self, device_key: str, last_ts_utc: str) -> None:
        async with self._lock:
            self._conn.execute(
                "INSERT INTO checkpoints(device_key, last_ts_utc) VALUES (?, ?) "
                "ON CONFLICT(device_key) DO UPDATE SET last_ts_utc=excluded.last_ts_utc",
                (device_key, last_ts_utc),
            )
            self._conn.commit()

    async def bump_failure(self, name: str) -> int:
        async with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            self._conn.execute(
                "INSERT INTO failures(name, consecutive, updated_at) VALUES (?, 1, ?) "
                "ON CONFLICT(name) DO UPDATE SET consecutive=failures.consecutive+1, updated_at=?",
                (name, now, now),
            )
            self._conn.commit()
            cur = self._conn.execute("SELECT consecutive FROM failures WHERE name=?", (name,))
            return int(cur.fetchone()[0])

    async def clear_failure(self, name: str) -> None:
        async with self._lock:
            self._conn.execute(
                "INSERT INTO failures(name, consecutive, updated_at) VALUES (?, 0, ?) "
                "ON CONFLICT(name) DO UPDATE SET consecutive=0, updated_at=?",
                (name, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()

# ---- UTIL --------------------------------------------------------------------

def backoff_delay(try_idx: int, base: float, max_s: float) -> float:
    # try_idx starts at 1
    delay = min(max_s, base ** try_idx)
    # small jitter
    return delay * (0.8 + 0.4 * os.urandom(1)[0] / 255.0)

def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def hash_checkin(device_id: str, user_id: str, ts_utc: str, log_type: Optional[str]) -> str:
    payload = f"{device_id}|{user_id}|{ts_utc}|{log_type or ''}"
    return hashlib.sha256(payload.encode()).hexdigest()

# ---- ALERTING ----------------------------------------------------------------

def send_alert(cfg: AppConfig, title: str, text: str) -> None:
    if not cfg.alerting.webhook_url:
        return
    payload = {"title": title, "text": text}
    try:
        requests.post(cfg.alerting.webhook_url, json=payload, timeout=10)
    except Exception:
        logger.exception("Failed to send alert")

# ---- ERP PUSH ----------------------------------------------------------------

import tzlocal  # Add this import at the top of your file

class ERPPusher:
    def __init__(self, cfg: ERPConfig, app_cfg: AppConfig):
        self.cfg = cfg
        self.app_cfg = app_cfg
        self.session = requests.Session()
        self.session.auth = (cfg.api_key, cfg.api_secret)
        self.session.verify = cfg.verify_tls

    def push(self, employee_field_value: str, timestamp_utc_iso: str, device_id: str, log_type: Optional[str]) -> None:
        from tzlocal import get_localzone

        url = self.cfg.base_url + self.cfg.endpoint
        headers = {
            "Content-Type": "application/json",
            "X-Idempotency-Key": hashlib.md5(
                f"{employee_field_value}|{timestamp_utc_iso}|{device_id}|{log_type}".encode()
            ).hexdigest(),
        }

        # Convert UTC → PC local time zone
        ts_dt = datetime.fromisoformat(timestamp_utc_iso)
        local_tz = get_localzone()  # e.g., Asia/Kolkata on your PC
        ts_local = ts_dt.astimezone(local_tz)

        payload = {
            "employee_field_value": employee_field_value,
            "timestamp": ts_local.replace(tzinfo=None).isoformat(sep=" "),  # Send in local PC time
            "device_id": device_id,
            "log_type": log_type,
            "employee_fieldname": self.cfg.employee_fieldname,
            "skip_auto_attendance": 0,
        }

        for attempt in range(1, self.app_cfg.max_push_retries + 1):
            try:
                resp = self.session.post(url, json=payload, headers=headers, timeout=self.cfg.timeout_secs)
                if resp.status_code == 200:
                    return
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise RuntimeError(f"ERP transient error {resp.status_code}: {resp.text[:300]}")
                raise RuntimeError(f"ERP error {resp.status_code}: {resp.text[:300]}")
            except Exception as e:
                if attempt >= self.app_cfg.max_push_retries:
                    raise
                delay = backoff_delay(attempt, self.app_cfg.backoff_base_seconds, self.app_cfg.backoff_max_seconds)
                logger.warning("Push retry %s after error: %s (sleep %.1fs)", attempt, e, delay)
                time.sleep(delay)


# ---- DEVICE ADAPTERS ---------------------------------------------------------

class LogRecord(Dict[str, Any]):
    """
    Keys:
      user_id (str)
      ts (datetime)    # in device local tz
      log_type (Optional[str])   # "IN"/"OUT" or None
    """
    pass

class DeviceAdapter:
    def __init__(self, cfg: DeviceConfig):
        self.cfg = cfg

    def fetch_since(self, since_dt: datetime) -> List[LogRecord]:
        """Return logs with ts >= since_dt (in device local tz)."""
        raise NotImplementedError

# ZKTeco via python-zk (blocking SDK, we'll run it in a thread)
class ZKAdapter(DeviceAdapter):
    def fetch_since(self, since_dt: datetime) -> List[LogRecord]:
        # Lazy import to keep optional dependency
        from zk import ZK, const

        logs: List[LogRecord] = []
        zk = ZK(self.cfg.ip, port=self.cfg.port, timeout=10, password=0, force_udp=False, ommit_ping=False)
        conn = None
        try:
            conn = zk.connect()
            # NOTE: Many devices don't support server-side filtering by time; fetch all recent and filter client-side.
            attendances = conn.get_attendance() or []
            local_tz = ZoneInfo(self.cfg.tz)
            for a in attendances:
                # python-zk provides .timestamp (naive datetime), .user_id, .status, .punch
                ts_local = a.timestamp.replace(tzinfo=local_tz)
                if ts_local >= since_dt:
                    lt = None
                    # Map status/punch to IN/OUT heuristically; customize per your devices
                    if getattr(a, "punch", None) in (0, 1) or getattr(a, "status", None) == const.USER_DEFAULT:
                        lt = None  # unknown
                    elif getattr(a, "punch", None) == 0:  # check-in
                        lt = "IN"
                    elif getattr(a, "punch", None) == 1:  # check-out
                        lt = "OUT"
                    logs.append(LogRecord(user_id=str(a.user_id), ts=ts_local, log_type=lt))
        finally:
            with contextlib.suppress(Exception):
                if conn:
                    conn.disconnect()
        # Sort by time ascending
        logs.sort(key=lambda r: r["ts"])
        return logs

def adapter_for(cfg: DeviceConfig) -> DeviceAdapter:
    proto = cfg.protocol.lower()
    if proto in ("zk", "zkteco", "python-zk"):
        return ZKAdapter(cfg)
    raise ValueError(f"Unsupported protocol '{cfg.protocol}' for device {cfg.name}")

# ---- WORKER LOGIC ------------------------------------------------------------

@dataclasses.dataclass
class SyncStats:
    device_name: str
    fetched: int = 0
    pushed: int = 0
    duplicates: int = 0
    newest_pushed_ts_utc: Optional[str] = None

class DeviceWorker:
    def __init__(self, app_cfg: AppConfig, store: Store, erp: ERPPusher, dev_cfg: DeviceConfig):
        self.app_cfg = app_cfg
        self.store = store
        self.erp = erp
        self.dev_cfg = dev_cfg
        self.adapter = adapter_for(dev_cfg)
        self.logger = logging.getLogger(f"device.{dev_cfg.name}")

    def _initial_since(self, now_local: datetime) -> datetime:
        # on first run, pull a limited window back
        return now_local - timedelta_minutes(self.dev_cfg.pull_batch_minutes)

    async def run_once(self, pool: concurrent.futures.Executor) -> SyncStats:
        stats = SyncStats(device_name=self.dev_cfg.name)
        local_tz = ZoneInfo(self.dev_cfg.tz)
        now_local = datetime.now(local_tz)
        # checkpoint
        cp = await self.store.get_checkpoint(self.dev_cfg.device_id)
        if cp:
            since_utc = datetime.fromisoformat(cp)
            since_local = since_utc.astimezone(local_tz)
        elif self.dev_cfg.start_from:
            try:
                # Parse ISO-style timestamp generated by validator
                since_local = datetime.fromisoformat(self.dev_cfg.start_from)
                if since_local.tzinfo is None:
                    since_local = since_local.replace(tzinfo=local_tz)
                else:
                    since_local = since_local.astimezone(local_tz)
                self.logger.info("Using configured start_from date: %s", since_local)
            except Exception as e:
                self.logger.error("Invalid start_from format for %s: %s", self.dev_cfg.name, e)
                since_local = self._initial_since(now_local)
        else:
            since_local = self._initial_since(now_local)

        # Fetch with retries (in thread)
        logs: List[LogRecord] = await self._fetch_with_retry(pool, since_local)
        stats.fetched = len(logs)

        newest_pushed: Optional[datetime] = None

        for rec in logs:
            # Normalize to UTC
            ts_utc = rec["ts"].astimezone(timezone.utc)
            ts_iso = iso_utc(ts_utc)
            h = hash_checkin(self.dev_cfg.device_id, rec["user_id"], ts_iso, rec.get("log_type"))

            # dedup (persistent)
            ok = await self.store.add_checkin(h, self.dev_cfg.device_id, rec["user_id"], ts_iso, rec.get("log_type"))
            if not ok:
                stats.duplicates += 1
                continue

            # Push to ERP with retries
            try:
                self.erp.push(
                    employee_field_value=rec["user_id"],
                    timestamp_utc_iso=ts_iso,
                    device_id=self.dev_cfg.device_id,
                    log_type=rec.get("log_type"),
                )
                stats.pushed += 1
                newest_pushed = max(newest_pushed, ts_utc) if newest_pushed else ts_utc
            except Exception as e:
                self.logger.exception("Failed to push record (user=%s ts=%s): %s", rec["user_id"], ts_iso, e)
                # bump failure counter, maybe alert
                fails = await self.store.bump_failure(self.dev_cfg.name)
                if fails >= self.app_cfg.alerting.min_consecutive_failures:
                    send_alert(
                        self.app_cfg,
                        f"[{self.dev_cfg.name}] ERP push failures",
                        f"Consecutive failures: {fails}\nLast error: {e}",
                    )
                # don't raise; continue to next record
            else:
                # success clears failure counter
                await self.store.clear_failure(self.dev_cfg.name)

        if newest_pushed:
            stats.newest_pushed_ts_utc = iso_utc(newest_pushed)
            await self.store.set_checkpoint(self.dev_cfg.device_id, stats.newest_pushed_ts_utc)

        self.logger.info(
            "cycle: fetched=%s pushed=%s dup=%s checkpoint=%s",
            stats.fetched, stats.pushed, stats.duplicates, stats.newest_pushed_ts_utc,
        )
        return stats

    async def _fetch_with_retry(self, pool: concurrent.futures.Executor, since_local: datetime) -> List[LogRecord]:
        for attempt in range(1, self.app_cfg.max_fetch_retries + 1):
            try:
                # Run blocking SDK in thread
                return await asyncio.get_event_loop().run_in_executor(pool, self.adapter.fetch_since, since_local)
            except Exception as e:
                if attempt >= self.app_cfg.max_fetch_retries:
                    raise
                delay = backoff_delay(attempt, self.app_cfg.backoff_base_seconds, self.app_cfg.backoff_max_seconds)
                self.logger.warning("Fetch retry %s after error: %s (sleep %.1fs)", attempt, e, delay)
                await asyncio.sleep(delay)

# ---- TIMING UTIL -------------------------------------------------------------

def timedelta_minutes(mins: int):
    from datetime import timedelta
    return timedelta(minutes=mins)

# ---- MAIN LOOP ---------------------------------------------------------------

class Runner:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.store = Store(cfg.sqlite_path)
        self.erp = ERPPusher(cfg.erp, cfg)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=cfg.max_workers)
        self.workers = [DeviceWorker(cfg, self.store, self.erp, d) for d in cfg.devices]
        self._stop = asyncio.Event()

    async def start(self):
        loop = asyncio.get_event_loop()
        try:
            # Works on Linux/macOS
            loop.add_signal_handler(signal.SIGINT, self._stop.set)
            loop.add_signal_handler(signal.SIGTERM, self._stop.set)
        except NotImplementedError:
            # Windows fallback: handle Ctrl+C differently
            import threading
            def watch_keyboard():
                try:
                    while not self._stop.is_set():
                        time.sleep(1)
                except KeyboardInterrupt:
                    self._stop.set()

            threading.Thread(target=watch_keyboard, daemon=True).start()

        logger.info("Starting biometric sync with %d devices. Poll interval: %ss", len(self.workers), self.cfg.poll_interval_seconds)
        while not self._stop.is_set():
            t0 = time.time()
            await asyncio.gather(*(w.run_once(self.pool) for w in self.workers))
            elapsed = time.time() - t0
            sleep_left = max(0, self.cfg.poll_interval_seconds - elapsed)
            await asyncio.wait([asyncio.create_task(self._stop.wait())], timeout=sleep_left)


        logger.info("Stopping...")
        self.pool.shutdown(wait=True)

# ---- ENTRY -------------------------------------------------------------------

def main():
    cfg = load_config()
    setup_logging(cfg)
    logger.info("Config loaded. Devices: %s", [d.name for d in cfg.devices])

    # Warn if ERP defaults are still present
    if "your-erp-instance.com" in cfg.erp.base_url.lower():
        logger.warning("ERP base_url looks like a placeholder. Please configure ERP credentials.")

    runner = Runner(cfg)
    try:
        asyncio.run(runner.start())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")

if __name__ == "__main__":
    main()