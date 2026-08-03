from __future__ import annotations

import ctypes
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import queue
import shutil
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "VirusTotalFolderChecker"
APP_VERSION = "4.0.0"
VT_API_BASE = "https://www.virustotal.com/api/v3"
PARTIAL_SUFFIXES = {".crdownload", ".part", ".partial", ".download", ".tmp"}
MAX_PUBLIC_UPLOAD_BYTES = 650 * 1024 * 1024
SMALL_UPLOAD_LIMIT_BYTES = 32 * 1024 * 1024


def app_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent

    return Path(__file__).resolve().parent


BASE_DIR = app_directory()
WATCH_DIR = BASE_DIR / "notchecked"
CLEAN_DIR = BASE_DIR / "dowload"
QUARANTINE_DIR = BASE_DIR / "quarantine"
CONFIG_PATH = BASE_DIR / "settings.json"
LOG_PATH = BASE_DIR / "virus_checker.log"

DEFAULT_CONFIG: dict[str, Any] = {
    "api_key": "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE",
    "upload_unknown_files": True,
    "minimum_scanner_results": 10,
    "request_interval_seconds": 16,
    "analysis_poll_seconds": 30,
    "analysis_timeout_minutes": 30,
    "folder_poll_seconds": 2,
    "scan_folder": "notchecked",
    "clean_folder": "dowload",
    "quarantine_folder": "quarantine",
    "move_failed_to_quarantine": False,
    "auto_start_monitoring": True,
}


def resolve_config_path(value: str, default_name: str) -> Path:
    raw = str(value or default_name).strip()
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = BASE_DIR / path
    return path.resolve()


def validate_folder_paths(scan_dir: Path, clean_dir: Path, quarantine_dir: Path | None = None) -> None:
    paths = [scan_dir.resolve(), clean_dir.resolve()]
    if quarantine_dir is not None:
        paths.append(quarantine_dir.resolve())

    if paths[0] == paths[1]:
        raise ValueError("Папка проверки и папка чистых файлов не могут совпадать.")
    if paths[0] in paths[1].parents or paths[1] in paths[0].parents:
        raise ValueError(
            "Папка проверки и папка чистых файлов не должны находиться одна внутри другой."
        )
    if quarantine_dir is not None:
        q = paths[2]
        if q == paths[0] or q == paths[1]:
            raise ValueError("Папка карантина не может совпадать с папкой проверки или чистых файлов.")
        if q in paths[0].parents or paths[0] in q.parents:
            raise ValueError("Папка карантина и папка проверки не должны находиться одна внутри другой.")
        if q in paths[1].parents or paths[1] in q.parents:
            raise ValueError("Папка карантина и папка чистых файлов не должны находиться одна внутри другой.")


def apply_config_paths(config: dict[str, Any]) -> None:
    global WATCH_DIR, CLEAN_DIR, QUARANTINE_DIR

    WATCH_DIR = resolve_config_path(str(config.get("scan_folder", "notchecked")), "notchecked")
    CLEAN_DIR = resolve_config_path(str(config.get("clean_folder", "dowload")), "dowload")
    QUARANTINE_DIR = resolve_config_path(
        str(config.get("quarantine_folder", "quarantine")), "quarantine"
    )
    validate_folder_paths(WATCH_DIR, CLEAN_DIR, QUARANTINE_DIR)
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    CLEAN_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    config["scan_folder"] = str(WATCH_DIR)
    config["clean_folder"] = str(CLEAN_DIR)
    config["quarantine_folder"] = str(QUARANTINE_DIR)


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def setup_logging() -> logging.Logger:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER = setup_logging()


def show_error(title: str, text: str) -> None:
    LOGGER.error(text.replace("\n", " | "))
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)
    except Exception:
        print(f"{title}: {text}")


def open_path(path: Path) -> None:
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1')
    except Exception:
        LOGGER.exception("Не удалось открыть: %s", path)


def acquire_single_instance() -> Any | None:
    if os.name != "nt":
        return object()

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool

    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(None, False, f"Local\\{APP_NAME}")
    if ctypes.get_last_error() == 183:
        if handle:
            kernel32.CloseHandle(handle)
        return None
    return handle


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        save_config(dict(DEFAULT_CONFIG))
        raise RuntimeError(
            "Первый запуск почти завершён.\n\n"
            "Откройте settings.json, вставьте API-ключ VirusTotal в поле api_key, "
            "сохраните файл и запустите программу снова."
        )

    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Не удалось прочитать settings.json:\n{exc}") from exc

    if not isinstance(raw, dict):
        raise RuntimeError("settings.json должен содержать JSON-объект.")

    config = DEFAULT_CONFIG | raw
    api_key = str(config.get("api_key", "")).strip()
    if not api_key or api_key == DEFAULT_CONFIG["api_key"]:
        raise RuntimeError("Укажите настоящий API-ключ VirusTotal в settings.json.")

    config["api_key"] = api_key
    config["upload_unknown_files"] = bool(config["upload_unknown_files"])
    config["move_failed_to_quarantine"] = bool(config["move_failed_to_quarantine"])
    config["minimum_scanner_results"] = max(1, int(config["minimum_scanner_results"]))
    config["request_interval_seconds"] = max(0.0, float(config["request_interval_seconds"]))
    config["analysis_poll_seconds"] = max(5.0, float(config["analysis_poll_seconds"]))
    config["analysis_timeout_minutes"] = max(1.0, float(config["analysis_timeout_minutes"]))
    config["folder_poll_seconds"] = max(1.0, float(config["folder_poll_seconds"]))
    config["auto_start_monitoring"] = bool(config["auto_start_monitoring"])
    apply_config_paths(config)
    return config


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wait_until_file_is_ready(
    path: Path,
    *,
    stable_checks: int = 3,
    check_interval: float = 1.5,
    max_wait_seconds: float = 600.0,
) -> bool:
    deadline = time.monotonic() + max_wait_seconds
    previous_signature: tuple[int, int] | None = None
    stable_count = 0

    while time.monotonic() < deadline:
        if not path.exists() or not path.is_file():
            return False
        try:
            stat = path.stat()
            signature = (stat.st_size, stat.st_mtime_ns)
            with path.open("rb") as handle:
                handle.read(1)
        except (OSError, PermissionError):
            stable_count = 0
            time.sleep(check_interval)
            continue

        if signature == previous_signature and stat.st_size > 0:
            stable_count += 1
        else:
            stable_count = 0
            previous_signature = signature

        if stable_count >= stable_checks:
            return True
        time.sleep(check_interval)

    return False


def unique_destination(directory: Path, original_name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / original_name
    if not candidate.exists():
        return candidate
    source = Path(original_name)
    for counter in range(1, 1_000_000):
        candidate = directory / f"{source.stem} ({counter}){source.suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError("Не удалось подобрать свободное имя файла.")


class VirusTotalClient:
    def __init__(self, config: dict[str, Any]) -> None:
        self._rate_lock = threading.Lock()
        self.update_config(config)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "x-apikey": self.api_key,
                "User-Agent": f"{APP_NAME}/{APP_VERSION}",
            }
        )
        self._last_request_at = 0.0

    def update_config(self, config: dict[str, Any]) -> None:
        self.api_key = str(config["api_key"])
        self.minimum_scanner_results = int(config["minimum_scanner_results"])
        self.request_interval = float(config["request_interval_seconds"])
        self.poll_interval = float(config["analysis_poll_seconds"])
        self.analysis_timeout = float(config["analysis_timeout_minutes"]) * 60
        self.upload_unknown_files = bool(config["upload_unknown_files"])
        if hasattr(self, "session"):
            self.session.headers.update({"x-apikey": self.api_key})

    def _respect_rate_limit(self) -> None:
        with self._rate_lock:
            remaining = self.request_interval - (time.monotonic() - self._last_request_at)
            if remaining > 0:
                time.sleep(remaining)
            self._last_request_at = time.monotonic()

    @staticmethod
    def error_text(response: requests.Response) -> str:
        try:
            payload = response.json()
            error = payload.get("error", {})
            if isinstance(error, dict):
                return str(error.get("message") or error.get("code") or payload)
            return str(payload)
        except (ValueError, AttributeError):
            return response.text[:500]

    def request(self, method: str, url: str, *, timeout: tuple[int, int] | int = (15, 300)) -> requests.Response:
        attempts = 4 if method.upper() == "GET" else 1
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            self._respect_rate_limit()
            try:
                response = self.session.request(method, url, timeout=timeout)
            except requests.RequestException as exc:
                last_error = exc
                if attempt == attempts:
                    raise RuntimeError(f"Ошибка сети VirusTotal: {exc}") from exc
                time.sleep(5 * attempt)
                continue

            if response.status_code == 429 and attempt < attempts:
                try:
                    delay = max(60, int(response.headers.get("Retry-After", "60")))
                except ValueError:
                    delay = 60
                LOGGER.warning("Лимит VirusTotal; пауза %s секунд.", delay)
                time.sleep(delay)
                continue
            if response.status_code >= 500 and attempt < attempts:
                time.sleep(5 * attempt)
                continue
            return response

        raise RuntimeError(f"Запрос VirusTotal не выполнен: {last_error}")

    def get_file_report(self, sha256: str) -> dict[str, Any] | None:
        response = self.request("GET", f"{VT_API_BASE}/files/{sha256}")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise RuntimeError(
                f"Ошибка получения отчёта ({response.status_code}): {self.error_text(response)}"
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("VirusTotal вернул неожиданный формат отчёта.")
        return payload

    def upload_file(self, path: Path) -> str:
        size = path.stat().st_size
        if size > MAX_PUBLIC_UPLOAD_BYTES:
            raise RuntimeError("Файл больше 650 МБ и не поддерживается обычной загрузкой.")

        upload_url = f"{VT_API_BASE}/files"
        if size > SMALL_UPLOAD_LIMIT_BYTES:
            response = self.request("GET", f"{VT_API_BASE}/files/upload_url")
            if response.status_code != 200:
                raise RuntimeError(
                    f"Не удалось получить URL загрузки ({response.status_code}): {self.error_text(response)}"
                )
            upload_url = str(response.json()["data"])

        LOGGER.info("Загрузка в VirusTotal: %s (%s байт)", path.name, size)
        self._respect_rate_limit()
        with path.open("rb") as handle:
            response = self.session.post(
                upload_url,
                files={"file": (path.name, handle, "application/octet-stream")},
                timeout=(30, 900),
            )
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Ошибка загрузки ({response.status_code}): {self.error_text(response)}"
            )
        try:
            return str(response.json()["data"]["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("VirusTotal не вернул идентификатор анализа.") from exc

    def wait_for_analysis(self, analysis_id: str) -> dict[str, int]:
        deadline = time.monotonic() + self.analysis_timeout
        while time.monotonic() < deadline:
            response = self.request("GET", f"{VT_API_BASE}/analyses/{analysis_id}")
            if response.status_code != 200:
                raise RuntimeError(
                    f"Ошибка проверки анализа ({response.status_code}): {self.error_text(response)}"
                )
            attributes = response.json().get("data", {}).get("attributes", {})
            if attributes.get("status") == "completed":
                stats = attributes.get("stats") or {}
                return {str(key): int(value) for key, value in stats.items()}
            LOGGER.info("Анализ ещё выполняется: %s", analysis_id)
            time.sleep(self.poll_interval)
        raise RuntimeError("Превышено время ожидания анализа VirusTotal.")

    @staticmethod
    def stats_from_report(report: dict[str, Any]) -> dict[str, int]:
        attributes = report.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or {}
        return {str(key): int(value) for key, value in stats.items()}

    def is_clean(self, stats: dict[str, int]) -> tuple[bool, str]:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        scanner_results = malicious + suspicious + harmless + undetected
        summary = (
            f"malicious={malicious}, suspicious={suspicious}, harmless={harmless}, "
            f"undetected={undetected}, результатов={scanner_results}"
        )
        clean = (
            malicious == 0
            and suspicious == 0
            and scanner_results >= self.minimum_scanner_results
        )
        return clean, summary

    def scan(self, path: Path) -> tuple[bool, str]:
        sha256 = sha256_file(path)
        LOGGER.info("SHA-256 %s: %s", path.name, sha256)

        report = self.get_file_report(sha256)
        if report is not None:
            stats = self.stats_from_report(report)
            if not stats:
                return False, "В существующем отчёте нет результатов антивирусов."
            return self.is_clean(stats)

        if not self.upload_unknown_files:
            return False, "Файл неизвестен VirusTotal; отправка отключена в настройках."

        analysis_id = self.upload_file(path)
        stats = self.wait_for_analysis(analysis_id)
        if not stats:
            return False, "VirusTotal завершил анализ без результатов антивирусов."
        return self.is_clean(stats)


@dataclass(frozen=True)
class ScanJob:
    path: Path
    auto_move: bool
    manual: bool


class ProcessingQueue:
    def __init__(self, client: VirusTotalClient, event_callback: Callable[[str, Any], None] | None = None) -> None:
        self.client = client
        self.items: queue.Queue[ScanJob] = queue.Queue()
        self._queued_paths: set[Path] = set()
        self._lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._stats = {"scanned": 0, "clean": 0, "attention": 0, "errors": 0}
        self._event_callback = event_callback
        self._worker = threading.Thread(target=self._run, name="VT-Worker", daemon=True)
        self._worker.start()

    def _event(self, kind: str, payload: Any = None) -> None:
        if self._event_callback:
            try:
                self._event_callback(kind, payload)
            except Exception:
                LOGGER.exception("Ошибка обработки события GUI: %s", kind)

    def queue_size(self) -> int:
        return self.items.qsize()

    def get_stats(self) -> dict[str, int]:
        with self._stats_lock:
            return dict(self._stats)

    def _inc_stat(self, key: str) -> None:
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + 1
            snapshot = dict(self._stats)
        self._event("stats", snapshot)

    def enqueue(self, path: Path, *, auto_move: bool = True, manual: bool = False) -> bool:
        try:
            path = path.resolve()
        except OSError:
            return False
        if not path.is_file() or path.suffix.lower() in PARTIAL_SUFFIXES:
            return False
        if not manual and path.parent != WATCH_DIR.resolve():
            return False

        with self._lock:
            if path in self._queued_paths:
                return False
            self._queued_paths.add(path)
            self.items.put(ScanJob(path=path, auto_move=auto_move, manual=manual))

        LOGGER.info("Добавлен в очередь: %s", path.name)
        self._event("status", f"В очереди: {self.queue_size()} | Добавлен: {path.name}")
        return True

    def clear_pending(self) -> int:
        removed = 0
        while True:
            try:
                job = self.items.get_nowait()
            except queue.Empty:
                break
            with self._lock:
                self._queued_paths.discard(job.path)
            self.items.task_done()
            removed += 1
        if removed:
            LOGGER.info("Из очереди удалено файлов: %s", removed)
            self._event("status", f"Очередь очищена: {removed} файлов")
        return removed

    def _run(self) -> None:
        while True:
            job = self.items.get()
            try:
                self._process(job)
            except Exception:
                self._inc_stat("errors")
                LOGGER.exception("Необработанная ошибка для файла %s", job.path)
                self._event("history", ("ОШИБКА", job.path.name, "Неожиданная ошибка обработки"))
            finally:
                with self._lock:
                    self._queued_paths.discard(job.path)
                self.items.task_done()
                self._event("status", f"Очередь: {self.queue_size()}")

    def _process(self, job: ScanJob) -> None:
        path = job.path
        self._event("status", f"Сканирование: {path.name}")
        if not wait_until_file_is_ready(path):
            self._inc_stat("errors")
            self._event("history", ("ПРОПУСК", path.name, "Файл не готов или исчез"))
            return

        try:
            clean, details = self.client.scan(path)
        except (OSError, RuntimeError, requests.RequestException) as exc:
            self._inc_stat("errors")
            LOGGER.error("Проверка не выполнена для %s: %s", path.name, exc)
            self._event("history", ("ОШИБКА", path.name, str(exc)))
            return

        self._inc_stat("scanned")
        if not path.exists():
            self._inc_stat("errors")
            self._event("history", ("ПРОПАЛ", path.name, "Файл исчез до завершения проверки"))
            return

        if clean:
            self._inc_stat("clean")
            if job.auto_move:
                destination = unique_destination(CLEAN_DIR, path.name)
                try:
                    shutil.move(str(path), str(destination))
                except OSError as exc:
                    self._inc_stat("errors")
                    self._event("history", ("ЧИСТО / ОШИБКА ПЕРЕМЕЩЕНИЯ", path.name, str(exc)))
                    return
                LOGGER.info("ЧИСТО: %s -> %s | %s", path.name, destination, details)
                self._event("history", ("ЧИСТО → ЧИСТЫЕ", path.name, details))
            else:
                self._event("history", ("ЧИСТО", path.name, details))
                self._event("manual_clean", (path, details))
        else:
            self._inc_stat("attention")
            LOGGER.warning("НЕ ПРОШЁЛ: %s | %s", path.name, details)
            if (not job.manual) and bool(APP_CONFIG.get("move_failed_to_quarantine", False)):
                try:
                    destination = unique_destination(QUARANTINE_DIR, path.name)
                    shutil.move(str(path), str(destination))
                    self._event("history", ("КАРАНТИН", path.name, details))
                    return
                except OSError as exc:
                    self._inc_stat("errors")
                    self._event("history", ("ТРЕБУЕТ ВНИМАНИЯ", path.name, f"Карантин не выполнен: {exc}"))
                    return
            self._event("history", ("НЕ ПРОШЁЛ", path.name, details))


class FolderMonitor:
    def __init__(self, processing_queue: ProcessingQueue, interval: float, event_callback: Callable[[str, Any], None] | None = None) -> None:
        self.processing_queue = processing_queue
        self.interval = max(1.0, interval)
        self.event_callback = event_callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: dict[Path, tuple[int, int]] = {}
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def start(self) -> None:
        with self._lock:
            if self.is_running:
                return
            self._stop_event.clear()
            self._seen.clear()
            self._thread = threading.Thread(target=self._run, name="VT-Monitor", daemon=True)
            self._thread.start()
        LOGGER.info("Автоматическое сканирование ВКЛЮЧЕНО: %s", WATCH_DIR)
        self._event("monitor", True)

    def stop(self) -> None:
        with self._lock:
            if self._thread is None:
                return
            self._stop_event.set()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        LOGGER.info("Автоматическое сканирование ВЫКЛЮЧЕНО.")
        self._event("monitor", False)

    def refresh_paths(self) -> None:
        self._seen.clear()

    def scan_existing(self) -> int:
        count = 0
        try:
            entries = list(WATCH_DIR.iterdir())
        except OSError as exc:
            LOGGER.error("Не удалось прочитать папку проверки: %s", exc)
            return 0
        for path in entries:
            if path.is_file() and path.suffix.lower() not in PARTIAL_SUFFIXES:
                if self.processing_queue.enqueue(path, auto_move=True, manual=False):
                    count += 1
        LOGGER.info("Ручная проверка папки: добавлено %s файлов.", count)
        return count

    def _scan_cycle(self) -> None:
        try:
            entries = list(WATCH_DIR.iterdir())
        except OSError as exc:
            LOGGER.error("Не удалось прочитать папку проверки: %s", exc)
            return

        current: set[Path] = set()
        for path in entries:
            if not path.is_file() or path.suffix.lower() in PARTIAL_SUFFIXES:
                continue
            try:
                resolved = path.resolve()
                stat = resolved.stat()
                signature = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                continue
            current.add(resolved)
            if self._seen.get(resolved) != signature:
                self._seen[resolved] = signature
                self.processing_queue.enqueue(resolved, auto_move=True, manual=False)

        for old_path in set(self._seen) - current:
            self._seen.pop(old_path, None)

    def _event(self, kind: str, payload: Any) -> None:
        if self.event_callback:
            self.event_callback(kind, payload)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._scan_cycle()
            self._stop_event.wait(self.interval)


APP_CONFIG: dict[str, Any] = dict(DEFAULT_CONFIG)


class GuiLogHandler(logging.Handler):
    def __init__(self, callback: Callable[[str], None]) -> None:
        super().__init__()
        self.callback = callback
        self.formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S")

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.callback(self.format(record))
        except Exception:
            pass


class Application:
    def __init__(self, root: tk.Tk, config: dict[str, Any], client: VirusTotalClient) -> None:
        global APP_CONFIG
        APP_CONFIG = config
        self.root = root
        self.config = config
        self.client = client
        self.event_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.processing_queue = ProcessingQueue(client, self._post_event)
        self.monitor = FolderMonitor(
            self.processing_queue,
            float(config["folder_poll_seconds"]),
            self._post_event,
        )
        self.log_handler = GuiLogHandler(lambda text: self._post_event("log", text))
        LOGGER.addHandler(self.log_handler)

        self.monitor_var = tk.StringVar()
        self.path_var = tk.StringVar()
        self.api_var = tk.StringVar()
        self.status_var = tk.StringVar()
        self.stats_var = tk.StringVar()
        self.upload_unknown_var = tk.BooleanVar(value=bool(config["upload_unknown_files"]))
        self.quarantine_var = tk.BooleanVar(value=bool(config["move_failed_to_quarantine"]))

        self._build_ui()
        self._load_log()
        self._refresh_ui()
        self.root.after(150, self._drain_events)

        if bool(config.get("auto_start_monitoring", True)):
            self.monitor.start()
            self.monitor.scan_existing()

    def _build_ui(self) -> None:
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1180x760")
        self.root.minsize(900, 620)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Button(top, textvariable=self.monitor_var, command=self.toggle_monitoring).grid(row=0, column=0, padx=4, pady=4)
        ttk.Button(top, text="Проверить файл", command=self.scan_file).grid(row=0, column=1, padx=4, pady=4)
        ttk.Button(top, text="Проверить папку", command=self.scan_folder).grid(row=0, column=2, padx=4, pady=4)
        ttk.Button(top, text="Выбрать папку проверки", command=self.pick_scan_folder).grid(row=0, column=3, padx=4, pady=4)
        ttk.Button(top, text="Выбрать папку чистых", command=self.pick_clean_folder).grid(row=0, column=4, padx=4, pady=4)
        ttk.Button(top, text="Открыть настройки", command=lambda: open_path(CONFIG_PATH)).grid(row=0, column=5, padx=4, pady=4)
        ttk.Button(top, text="Обновить", command=self.reload_settings).grid(row=0, column=6, padx=4, pady=4)
        ttk.Button(top, text="Очистить очередь", command=self.clear_queue).grid(row=0, column=7, padx=4, pady=4)

        ttk.Label(self.root, textvariable=self.path_var, padding=(14, 2)).pack(fill="x")
        ttk.Label(self.root, textvariable=self.api_var, padding=(14, 2)).pack(fill="x")
        ttk.Label(self.root, textvariable=self.status_var, padding=(14, 2)).pack(fill="x")
        ttk.Label(self.root, textvariable=self.stats_var, padding=(14, 2)).pack(fill="x")

        options = ttk.Frame(self.root, padding=(10, 4))
        options.pack(fill="x")
        ttk.Checkbutton(
            options,
            text="Отправлять неизвестные файлы на анализ VirusTotal",
            variable=self.upload_unknown_var,
            command=self.toggle_upload_unknown,
        ).pack(side="left", padx=4)
        ttk.Checkbutton(
            options,
            text="Непрошедшие проверку → карантин",
            variable=self.quarantine_var,
            command=self.toggle_quarantine,
        ).pack(side="left", padx=20)

        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=8)

        history_frame = ttk.Labelframe(body, text="История", padding=6)
        log_frame = ttk.Labelframe(body, text="Живой лог", padding=6)
        body.add(history_frame, weight=1)
        body.add(log_frame, weight=2)

        columns = ("time", "status", "file", "details")
        self.history = ttk.Treeview(history_frame, columns=columns, show="headings")
        self.history.heading("time", text="Время")
        self.history.heading("status", text="Статус")
        self.history.heading("file", text="Файл")
        self.history.heading("details", text="Подробности")
        self.history.column("time", width=80, stretch=False)
        self.history.column("status", width=170, stretch=False)
        self.history.column("file", width=220)
        self.history.column("details", width=320)
        history_scroll = ttk.Scrollbar(history_frame, orient="vertical", command=self.history.yview)
        self.history.configure(yscrollcommand=history_scroll.set)
        self.history.pack(side="left", fill="both", expand=True)
        history_scroll.pack(side="right", fill="y")

        self.log_text = tk.Text(log_frame, wrap="none", state="disabled")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        bottom = ttk.Frame(self.root, padding=10)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Открыть папку проверки", command=lambda: open_path(WATCH_DIR)).pack(side="left", padx=4)
        ttk.Button(bottom, text="Открыть папку чистых", command=lambda: open_path(CLEAN_DIR)).pack(side="left", padx=4)
        ttk.Button(bottom, text="Открыть карантин", command=lambda: open_path(QUARANTINE_DIR)).pack(side="left", padx=4)
        ttk.Button(bottom, text="Открыть лог", command=lambda: open_path(LOG_PATH)).pack(side="left", padx=4)
        ttk.Button(bottom, text="Очистить отображение лога", command=self.clear_log_view).pack(side="right", padx=4)
        ttk.Button(bottom, text="Очистить историю", command=self.clear_history).pack(side="right", padx=4)

    def _post_event(self, kind: str, payload: Any = None) -> None:
        self.event_queue.put((kind, payload))
        try:
            self.root.after_idle(lambda: None)
        except tk.TclError:
            pass

    def _load_log(self) -> None:
        try:
            if LOG_PATH.exists():
                lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
                self._append_log("\n".join(lines))
        except OSError:
            pass

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        if int(self.log_text.index("end-1c").split(".")[0]) > 8000:
            self.log_text.delete("1.0", "1000.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _add_history(self, status: str, filename: str, details: str) -> None:
        self.history.insert("", "end", values=(time.strftime("%H:%M:%S"), status, filename, details))
        items = self.history.get_children()
        if len(items) > 300:
            self.history.delete(items[0])
        self.history.yview_moveto(1.0)

    def _refresh_ui(self) -> None:
        self.monitor_var.set("Автосканирование: ВКЛ" if self.monitor.is_running else "Автосканирование: ВЫКЛ")
        self.path_var.set(f"Проверка: {WATCH_DIR}    |    Чистые: {CLEAN_DIR}    |    Карантин: {QUARANTINE_DIR}")
        key = str(self.config.get("api_key", ""))
        masked = (key[:6] + "…" + key[-4:]) if len(key) >= 12 else "не установлен"
        self.api_var.set(f"API-ключ: {masked}")
        self.status_var.set(f"Статус: {'работает' if self.monitor.is_running else 'выключено'}    |    Очередь: {self.processing_queue.queue_size()}")
        stats = self.processing_queue.get_stats()
        self.stats_var.set(
            f"Проверено: {stats['scanned']}    |    Чистых: {stats['clean']}    |    Требуют внимания: {stats['attention']}    |    Ошибок: {stats['errors']}    |    В очереди: {self.processing_queue.queue_size()}"
        )

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "status":
                    self.status_var.set(f"Статус: {'работает' if self.monitor.is_running else 'выключено'}    |    {payload}")
                elif kind == "history":
                    status, filename, details = payload
                    self._add_history(status, filename, details)
                elif kind == "manual_clean":
                    path, details = payload
                    self._handle_manual_clean(Path(path), str(details))
                elif kind == "stats":
                    pass
                elif kind == "monitor":
                    self.monitor_var.set("Автосканирование: ВКЛ" if payload else "Автосканирование: ВЫКЛ")
        except queue.Empty:
            pass
        self._refresh_ui()
        try:
            self.root.after(150, self._drain_events)
        except tk.TclError:
            pass

    def toggle_monitoring(self) -> None:
        if self.monitor.is_running:
            self.monitor.stop()
            self.config["auto_start_monitoring"] = False
        else:
            self.monitor.start()
            self.config["auto_start_monitoring"] = True
            self.monitor.scan_existing()
        self._persist_config()
        self._refresh_ui()

    def scan_file(self) -> None:
        path = filedialog.askopenfilename(title="Выберите файл для проверки VirusTotal")
        if not path:
            return
        if not self.processing_queue.enqueue(Path(path), auto_move=False, manual=True):
            messagebox.showwarning(APP_NAME, "Не удалось добавить файл в очередь.")

    def scan_folder(self) -> None:
        count = self.monitor.scan_existing()
        messagebox.showinfo(APP_NAME, f"Добавлено в очередь: {count} файлов.")

    def pick_scan_folder(self) -> None:
        chosen = filedialog.askdirectory(title="Выберите папку для автоматической проверки", initialdir=str(WATCH_DIR))
        if not chosen:
            return
        self._apply_paths(Path(chosen), CLEAN_DIR, QUARANTINE_DIR)

    def pick_clean_folder(self) -> None:
        chosen = filedialog.askdirectory(title="Выберите папку для чистых файлов", initialdir=str(CLEAN_DIR))
        if not chosen:
            return
        self._apply_paths(WATCH_DIR, Path(chosen), QUARANTINE_DIR)

    def _apply_paths(self, scan_dir: Path, clean_dir: Path, quarantine_dir: Path) -> None:
        try:
            validate_folder_paths(scan_dir, clean_dir, quarantine_dir)
            scan_dir.mkdir(parents=True, exist_ok=True)
            clean_dir.mkdir(parents=True, exist_ok=True)
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            self.config["scan_folder"] = str(scan_dir.resolve())
            self.config["clean_folder"] = str(clean_dir.resolve())
            self.config["quarantine_folder"] = str(quarantine_dir.resolve())
            apply_config_paths(self.config)
            self.monitor.refresh_paths()
            self._persist_config()
            self._refresh_ui()
        except (OSError, ValueError) as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def toggle_upload_unknown(self) -> None:
        self.config["upload_unknown_files"] = bool(self.upload_unknown_var.get())
        self.client.update_config(self.config)
        self._persist_config()
        LOGGER.info("Отправка неизвестных файлов: %s", self.config["upload_unknown_files"])

    def toggle_quarantine(self) -> None:
        self.config["move_failed_to_quarantine"] = bool(self.quarantine_var.get())
        APP_CONFIG["move_failed_to_quarantine"] = self.config["move_failed_to_quarantine"]
        self._persist_config()
        LOGGER.info("Автокарантин: %s", self.config["move_failed_to_quarantine"])

    def reload_settings(self) -> None:
        try:
            config = load_config()
            apply_config_paths(config)
        except (RuntimeError, OSError, ValueError) as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        global APP_CONFIG
        APP_CONFIG = config
        self.config = config
        self.client.update_config(config)
        self.monitor.interval = float(config["folder_poll_seconds"])
        self.monitor.refresh_paths()
        self.upload_unknown_var.set(bool(config["upload_unknown_files"]))
        self.quarantine_var.set(bool(config["move_failed_to_quarantine"]))
        self._refresh_ui()
        LOGGER.info("Настройки перечитаны из settings.json.")

    def clear_queue(self) -> None:
        removed = self.processing_queue.clear_pending()
        messagebox.showinfo(APP_NAME, f"Удалено из очереди: {removed}\nТекущая проверка, если она уже идёт, будет завершена.")

    def _handle_manual_clean(self, path: Path, details: str) -> None:
        if not path.exists():
            return
        answer = messagebox.askyesno(
            APP_NAME,
            f"VirusTotal не обнаружил срабатываний.\n\nФайл: {path.name}\n{details}\n\nПереместить файл в папку чистых?",
        )
        if answer:
            try:
                destination = unique_destination(CLEAN_DIR, path.name)
                shutil.move(str(path), str(destination))
                LOGGER.info("Ручной перенос чистого файла: %s -> %s", path.name, destination)
                self._add_history("РУЧНОЙ ПЕРЕНОС", path.name, str(destination))
            except OSError as exc:
                messagebox.showerror(APP_NAME, f"Не удалось переместить файл:\n{exc}")

    def clear_log_view(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def clear_history(self) -> None:
        for item in self.history.get_children():
            self.history.delete(item)

    def _persist_config(self) -> None:
        try:
            save_config(self.config)
        except OSError as exc:
            LOGGER.error("Не удалось сохранить настройки: %s", exc)

    def close(self) -> None:
        self.config["auto_start_monitoring"] = self.monitor.is_running
        self._persist_config()
        self.monitor.stop()
        try:
            LOGGER.removeHandler(self.log_handler)
        except ValueError:
            pass
        self.root.destroy()


def run() -> int:
    instance_handle = acquire_single_instance()
    if instance_handle is None:
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                "VirusTotalFolderChecker уже запущен.",
                APP_NAME,
                0x40,
            )
        except Exception:
            pass
        return 0

    try:
        config = load_config()
    except RuntimeError as exc:
        show_error(APP_NAME, str(exc))
        return 1

    try:
        apply_config_paths(config)
        client = VirusTotalClient(config)
        root = tk.Tk()
        app = Application(root, config, client)
        root.mainloop()
        return 0
    except Exception as exc:
        LOGGER.exception("Критическая ошибка")
        show_error(APP_NAME, f"Критическая ошибка:\n{exc}\n\nСмотрите virus_checker.log.")
        return 2
    finally:
        if os.name == "nt" and instance_handle:
            try:
                ctypes.windll.kernel32.CloseHandle(instance_handle)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(run())
