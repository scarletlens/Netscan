from __future__ import annotations

import json
import re
import socket
import ssl
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from html import unescape
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from html.parser import HTMLParser
from pathlib import Path
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
DEFAULT_HEADERS = {
    "User-Agent": "netscan/0.1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "close",
}
HTTP_PORTS = {80, 8000, 8080, 8888}
HTTPS_PORTS = {443, 4443, 8443}
TCP_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    389: "ldap",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5672: "amqp",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    9300: "elasticsearch-node",
    11211: "memcached",
    27017: "mongodb",
}
RISK_PATH_GROUPS = {
    "基础线索": [
        "/robots.txt",
        "/sitemap.xml",
    ],
    "登录入口": [
        "/login",
        "/signin",
        "/sign-in",
        "/user/login",
        "/auth/login",
        "/account/login",
        "/member/login",
        "/passport/login",
        "/admin/login",
    ],
    "后台入口": [
        "/admin",
        "/dashboard",
        "/console",
        "/manage",
        "/manager",
        "/backend",
        "/system",
        "/cpanel",
        "/admin/index",
    ],
    "接口文档": [
        "/swagger",
        "/swagger-ui",
        "/swagger-ui.html",
        "/openapi.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/redoc",
    ],
    "调试与监控": [
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/phpinfo.php",
        "/server-status",
        "/debug",
        "/metrics",
    ],
    "敏感文件": [
        "/.env",
        "/.git/config",
        "/config.js",
        "/backup.zip",
        "/backup.tar.gz",
        "/dump.sql",
        "/.DS_Store",
    ],
}
INTERESTING_PATHS = [path for group in RISK_PATH_GROUPS.values() for path in group]


@dataclass(slots=True)
class ScanConfig:
    targets: list[str]
    ports: list[int]
    concurrency: int
    rate: float
    timeout: float
    archive_dir: Path
    crawl_depth: int
    max_pages: int


@dataclass(slots=True)
class ScanJob:
    input_target: str
    url: str
    host: str
    port: int
    scheme: str
    path: str
    depth: int = 0


@dataclass(slots=True)
class ScanResult:
    input_target: str
    url: str
    host: str
    port: int
    scheme: str
    ok: bool
    latency_ms: int
    service: str | None = None
    transport: str | None = None
    status: int | None = None
    reason: str | None = None
    server: str | None = None
    title: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    redirect_location: str | None = None
    cookies: list[str] | None = None
    exposures: list[str] | None = None
    page_signals: list[str] | None = None
    discovered_urls: list[str] | None = None
    methods: list[str] | None = None
    findings: list[str] | None = None
    risk_level: str | None = None
    risk_details: list[dict[str, str]] | None = None
    error: str | None = None


class ScanObserver(Protocol):
    def on_start(self, total: int, run_id: str, run_path: Path, config: ScanConfig) -> None: ...

    def on_result(self, result: ScanResult, stats: dict[str, int]) -> None: ...

    def on_finish(self, summary: dict) -> None: ...


class RateLimiter:
    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._min_interval = 1.0 / rate
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next = max(self._next, now) + self._min_interval


class ProgressTracker:
    def __init__(self, total: int) -> None:
        self.total = total
        self.completed = 0
        self.success = 0
        self.failed = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._render_loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def update(self, result: ScanResult) -> None:
        with self._lock:
            self.completed += 1
            if result.ok:
                self.success += 1
            else:
                self.failed += 1

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()
        print("", flush=True)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "total": self.total,
                "completed": self.completed,
                "success": self.success,
                "failed": self.failed,
            }

    def _render_loop(self) -> None:
        while not self._stop.is_set():
            snap = self.snapshot()
            total = max(snap["total"], 1)
            pct = snap["completed"] / total * 100
            line = (
                f"\r进度 {snap['completed']}/{snap['total']} "
                f"({pct:5.1f}%)  成功={snap['success']} 失败={snap['failed']}"
            )
            print(line, end="", flush=True)
            self._stop.wait(0.2)


class ConsoleObserver:
    def __init__(self, total: int) -> None:
        self.progress = ProgressTracker(total)

    def on_start(self, total: int, run_id: str, run_path: Path, config: ScanConfig) -> None:
        self.progress.start()

    def on_result(self, result: ScanResult, stats: dict[str, int]) -> None:
        self.progress.update(result)

    def on_finish(self, summary: dict) -> None:
        self.progress.stop()


class NullObserver:
    def on_start(self, total: int, run_id: str, run_path: Path, config: ScanConfig) -> None:
        return None

    def on_result(self, result: ScanResult, stats: dict[str, int]) -> None:
        return None

    def on_finish(self, summary: dict) -> None:
        return None


class ArchiveWriter:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir

    def prepare_run(self, targets: list[str]) -> tuple[str, Path]:
        run_id = datetime.now(UTC).strftime("run-%Y%m%dT%H%M%SZ")
        run_label = make_archive_label(targets, run_id)
        run_path = self.base_dir / run_label
        run_path.mkdir(parents=True, exist_ok=True)
        return run_id, run_path

    def write(self, run_path: Path, payload: dict) -> None:
        summary_path = run_path / "summary.json"
        results_path = run_path / "results.ndjson"
        summary_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        with results_path.open("w", encoding="utf-8") as handle:
            for result in payload["results"]:
                handle.write(json.dumps(result, ensure_ascii=False) + "\n")


def make_archive_label(targets: list[str], run_id: str) -> str:
    primary = targets[0] if targets else "target"
    primary = primary.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
    primary = re.sub(r"[^a-zA-Z0-9._-]+", "_", primary).strip("._-")
    if not primary:
        primary = "target"
    if len(targets) > 1:
        primary = f"{primary}_and_{len(targets) - 1}_more"
    return f"{primary}-{run_id}"


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attr_map = dict(attrs)
        href = attr_map.get("href")
        if href:
            self.links.append(href)


def normalize_job(target: str, ports: list[int]) -> list[ScanJob]:
    if "://" in target:
        parts = urlsplit(target)
        if not parts.hostname:
            raise ValueError(f"invalid target URL: {target}")
        scheme = parts.scheme or "http"
        port = parts.port or (443 if scheme == "https" else 80)
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        return [
            ScanJob(
                input_target=target,
                url=urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, "")),
                host=parts.hostname,
                port=port,
                scheme=scheme,
                path=path,
                depth=0,
            )
        ]

    jobs: list[ScanJob] = []
    for port in ports:
        if port in HTTPS_PORTS:
            scheme = "https"
        elif port in HTTP_PORTS:
            scheme = "http"
        else:
            scheme = "tcp"
        jobs.append(
            ScanJob(
                input_target=target,
                url=f"{scheme}://{target}:{port}/" if scheme != "tcp" else f"tcp://{target}:{port}",
                host=target,
                port=port,
                scheme=scheme,
                path="/",
                depth=0,
            )
        )
    return jobs


def build_jobs(targets: list[str], ports: list[int]) -> list[ScanJob]:
    jobs: list[ScanJob] = []
    for target in targets:
        jobs.extend(normalize_job(target, ports))
    return jobs


def extract_title(body: str) -> str | None:
    match = TITLE_RE.search(body)
    if not match:
        return None
    collapsed = " ".join(unescape(match.group(1)).split())
    return collapsed[:200] if collapsed else None


def build_risk(
    severity: str,
    title: str,
    evidence: str,
    suggestion: str,
) -> dict[str, str]:
    return {
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "suggestion": suggestion,
    }


def guess_service(port: int, scheme: str, server: str | None = None) -> str:
    if scheme == "https":
        return "https"
    if scheme == "http":
        return "http"
    if port in TCP_SERVICE_MAP:
        return TCP_SERVICE_MAP[port]
    if server:
        return server.lower().split("/")[0]
    return "unknown"


def analyze_headers(
    scheme: str,
    headers: dict[str, str],
    methods: list[str],
    status: int,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    normalized = {key.lower(): value for key, value in headers.items()}

    if "content-security-policy" not in normalized:
        findings.append(build_risk("low", "缺少 CSP", "响应头未发现 Content-Security-Policy", "检查页面是否存在脚本注入面，并补充 CSP 策略"))
    if "x-frame-options" not in normalized:
        findings.append(build_risk("low", "缺少 X-Frame-Options", "响应头未发现 X-Frame-Options", "确认页面是否允许被 iframe 嵌套，必要时限制 frame 来源"))
    if "x-content-type-options" not in normalized:
        findings.append(build_risk("low", "缺少 X-Content-Type-Options", "响应头未发现 X-Content-Type-Options", "建议设置 nosniff，减少 MIME 嗅探风险"))
    if scheme == "https" and "strict-transport-security" not in normalized:
        findings.append(build_risk("medium", "缺少 HSTS", "HTTPS 响应未发现 Strict-Transport-Security", "确认是否需要强制浏览器仅通过 HTTPS 访问"))
    if normalized.get("server"):
        findings.append(build_risk("info", "Server 响应头暴露服务信息", f"Server: {normalized.get('server')}", "确认是否需要隐藏或统一服务指纹"))
    if 300 <= status < 400 and normalized.get("location"):
        findings.append(build_risk("info", "存在重定向链", f"Location: {normalized.get('location')}", "检查跳转目标是否符合预期，避免开放重定向或异常流转"))
    if "trace" in {method.upper() for method in methods}:
        findings.append(build_risk("medium", "允许 TRACE 方法", f"Allow: {','.join(methods)}", "确认服务器是否需要关闭 TRACE"))
    if normalized.get("set-cookie") and "secure" not in normalized.get("set-cookie", "").lower():
        findings.append(build_risk("medium", "Cookie 可能缺少 Secure 属性", normalized.get("set-cookie", ""), "确认敏感 Cookie 是否仅通过 HTTPS 传输"))
    if normalized.get("set-cookie") and "httponly" not in normalized.get("set-cookie", "").lower():
        findings.append(build_risk("medium", "Cookie 可能缺少 HttpOnly 属性", normalized.get("set-cookie", ""), "确认会话 Cookie 是否应禁止脚本访问"))
    return findings


def detect_page_signals(title: str | None, body: str, url: str) -> list[str]:
    signals: list[str] = []
    haystack = f"{title or ''} {body[:2000]} {url}".lower()
    if any(keyword in haystack for keyword in ["login", "signin", "sign in", "登录"]):
        signals.append("疑似登录页")
    if any(keyword in haystack for keyword in ["admin", "dashboard", "后台", "管理"]):
        signals.append("疑似后台页")
    if any(keyword in haystack for keyword in ["swagger", "openapi"]):
        signals.append("疑似接口文档页")
    if any(keyword in haystack for keyword in ["reset password", "forgot password", "找回密码"]):
        signals.append("存在密码找回入口线索")
    return signals


def classify_exposure(path_hit: str) -> tuple[str, str]:
    path = path_hit.split(" 返回 ", 1)[0]
    for group, paths in RISK_PATH_GROUPS.items():
        if path in paths:
            return group, path
    return "其他路径", path


def exposure_status(path_hit: str) -> int | None:
    if " 返回 " not in path_hit:
        return None
    raw = path_hit.rsplit(" 返回 ", 1)[1].strip()
    return int(raw) if raw.isdigit() else None


def risks_from_signals(signals: list[str], exposures: list[str]) -> list[dict[str, str]]:
    risks: list[dict[str, str]] = []
    for signal in signals:
        if signal == "疑似后台页":
            risks.append(build_risk("medium", "发现后台入口线索", signal, "确认后台是否存在未授权访问、弱口令或暴露信息"))
        elif signal == "疑似登录页":
            risks.append(build_risk("info", "发现登录页线索", signal, "人工检查认证流程、错误提示和找回密码逻辑"))
        elif signal == "疑似接口文档页":
            risks.append(build_risk("medium", "发现接口文档线索", signal, "确认 Swagger/OpenAPI 页面是否应对外开放"))
        elif signal == "存在密码找回入口线索":
            risks.append(build_risk("info", "发现密码找回入口线索", signal, "人工确认找回流程是否存在枚举或逻辑问题"))
    for exposure in exposures:
        category, path = classify_exposure(exposure)
        if path == "/.env" and "200" in exposure:
            risks.append(build_risk("high", "敏感配置文件可能暴露", exposure, "立即人工确认内容是否可读，并检查是否泄露密钥"))
        elif category == "登录入口":
            risks.append(build_risk("medium", "发现登录入口路径", exposure, "人工检查登录流程、验证码、错误提示和找回密码逻辑"))
        elif category == "后台入口":
            risks.append(build_risk("medium", "发现后台入口路径", exposure, "人工确认是否存在未授权访问、默认口令或信息暴露"))
        elif category == "接口文档":
            risks.append(build_risk("medium", "发现接口文档路径", exposure, "确认接口文档是否应对外开放，并检查是否泄露接口定义"))
        elif category == "调试与监控":
            risks.append(build_risk("medium", "发现调试或监控路径", exposure, "确认调试、监控和健康检查页面是否应暴露给外部"))
        elif category == "敏感文件":
            risks.append(build_risk("high" if "200" in exposure else "medium", "发现敏感文件路径", exposure, "人工确认该文件是否可读，以及是否包含配置、备份或源码线索"))
        else:
            risks.append(build_risk("info", f"发现{category}线索", exposure, "确认该路径是否应对外暴露"))
    return risks


def build_exposure_result(parent: ScanResult, exposure: str) -> ScanResult:
    category, path = classify_exposure(exposure)
    status = exposure_status(exposure)
    risk_details = risks_from_signals([], [exposure])
    risk_level, findings = summarize_risks(risk_details)
    return ScanResult(
        input_target=parent.input_target,
        url=f"{parent.scheme}://{parent.host}:{parent.port}{path}",
        host=parent.host,
        port=parent.port,
        scheme=parent.scheme,
        ok=True,
        latency_ms=parent.latency_ms,
        service=parent.service,
        transport=parent.transport,
        status=status,
        reason=category,
        server=parent.server,
        title=f"{category} 命中",
        content_type=parent.content_type,
        methods=parent.methods,
        findings=findings,
        risk_level=risk_level,
        risk_details=risk_details,
    )


def merge_risks(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    merged: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for group in groups:
        for item in group:
            key = (item["title"], item["evidence"])
            if key in seen:
                continue
            merged.append(item)
            seen.add(key)
    return merged


def summarize_risks(risks: list[dict[str, str]]) -> tuple[str, list[str]]:
    if not risks:
        return "info", []
    order = {"high": 3, "medium": 2, "low": 1, "info": 0}
    top = max((risk["severity"] for risk in risks), key=lambda item: order.get(item, 0))
    findings = [f"[{risk['severity'].upper()}] {risk['title']}" for risk in risks]
    return top, findings


def analyze_cookies(headers: dict[str, str]) -> list[str]:
    cookies: list[str] = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie_name = value.split("=", 1)[0].strip()
            flags = []
            lowered = value.lower()
            if "secure" in lowered:
                flags.append("Secure")
            if "httponly" in lowered:
                flags.append("HttpOnly")
            if "samesite" in lowered:
                flags.append("SameSite")
            cookies.append(f"{cookie_name} [{'/'.join(flags) if flags else '无安全属性'}]")
    return cookies


def inspect_interesting_paths(job: ScanJob, timeout: float) -> list[str]:
    if job.path != "/":
        return []
    hits: list[str] = []
    for path in INTERESTING_PATHS:
        response = send_http_request(job, timeout, "GET", path)
        if response is None:
            continue
        status, _, headers, _ = response
        if status in {200, 401, 403}:
            hits.append(f"{path} 返回 {status}")
    return hits


def extract_links(job: ScanJob, body: str) -> list[str]:
    extractor = LinkExtractor()
    try:
        extractor.feed(body)
    except Exception:  # noqa: BLE001
        return []
    discovered: list[str] = []
    seen: set[str] = set()
    base = f"{job.scheme}://{job.host}:{job.port}{job.path}"
    for href in extractor.links:
        if href.startswith(("javascript:", "mailto:", "#")):
            continue
        absolute = urljoin(base, href)
        parts = urlsplit(absolute)
        if parts.hostname != job.host or parts.scheme != job.scheme or (parts.port or job.port) != job.port:
            continue
        normalized = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
        if normalized not in seen:
            discovered.append(normalized)
            seen.add(normalized)
    return discovered[:20]


def create_connection(job: ScanJob, timeout: float) -> HTTPConnection | HTTPSConnection:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if job.scheme == "https":
        return HTTPSConnection(
            host=job.host,
            port=job.port,
            timeout=timeout,
            context=context,
        )
    return HTTPConnection(host=job.host, port=job.port, timeout=timeout)


def send_http_request(
    job: ScanJob,
    timeout: float,
    method: str,
    path: str,
) -> tuple[int, str, dict[str, str], str] | None:
    connection = create_connection(job, timeout)
    try:
        connection.request(method, path, headers=DEFAULT_HEADERS)
        response: HTTPResponse = connection.getresponse()
        body = response.read(8192).decode("utf-8", errors="ignore")
        headers = {key: value for key, value in response.getheaders()}
        return response.status, response.reason, headers, body
    except Exception:  # noqa: BLE001
        return None
    finally:
        connection.close()


def probe_methods(connection: HTTPConnection | HTTPSConnection, path: str) -> list[str]:
    return []


def fetch_http(job: ScanJob, timeout: float) -> ScanResult:
    started = time.perf_counter()
    try:
        with socket.create_connection((job.host, job.port), timeout=timeout):
            pass
    except OSError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return ScanResult(
            input_target=job.input_target,
            url=job.url,
            host=job.host,
            port=job.port,
            scheme=job.scheme,
            ok=False,
            latency_ms=latency_ms,
            service=guess_service(job.port, job.scheme),
            transport="tcp",
            error=f"tcp_connect_failed: {exc}",
        )

    if job.scheme == "tcp":
        latency_ms = int((time.perf_counter() - started) * 1000)
        service = guess_service(job.port, job.scheme)
        return ScanResult(
            input_target=job.input_target,
            url=job.url,
            host=job.host,
            port=job.port,
            scheme=job.scheme,
            ok=True,
            latency_ms=latency_ms,
            service=service,
            transport="tcp",
            findings=[f"[INFO] 发现开放端口 {job.port} ({service})"],
            risk_level="info",
            risk_details=[
                build_risk("info", "发现开放端口", f"{job.host}:{job.port} ({service})", "确认该端口上的服务是否应对外开放，并继续人工核对版本与鉴权")
            ],
        )

    try:
        get_response = send_http_request(job, timeout, "GET", job.path)
        if get_response is None:
            raise OSError("no_http_response")
        status, reason, header_map, body = get_response
        options_response = send_http_request(job, timeout, "OPTIONS", job.path)
        methods = []
        if options_response is not None:
            allow = options_response[2].get("Allow", "")
            methods = [part.strip().upper() for part in allow.split(",") if part.strip()]
        exposures = inspect_interesting_paths(job, timeout)
        page_title = extract_title(body)
        page_signals = detect_page_signals(page_title, body, job.url)
        discovered_urls = extract_links(job, body) if "html" in (header_map.get("Content-Type", "").lower()) else []
        header_risks = analyze_headers(job.scheme, header_map, methods, status)
        signal_risks = risks_from_signals(page_signals, exposures)
        risk_details = merge_risks(header_risks, signal_risks)
        risk_level, findings = summarize_risks(risk_details)
        latency_ms = int((time.perf_counter() - started) * 1000)
        return ScanResult(
            input_target=job.input_target,
            url=job.url,
            host=job.host,
            port=job.port,
            scheme=job.scheme,
            ok=True,
            latency_ms=latency_ms,
            service=guess_service(job.port, job.scheme, header_map.get("Server")),
            transport="tcp",
            status=status,
            reason=reason,
            server=header_map.get("Server"),
            title=page_title,
            content_type=header_map.get("Content-Type"),
            content_length=int(header_map["Content-Length"]) if header_map.get("Content-Length", "").isdigit() else None,
            redirect_location=header_map.get("Location"),
            cookies=analyze_cookies(header_map),
            exposures=exposures,
            page_signals=page_signals,
            discovered_urls=discovered_urls,
            methods=methods,
            findings=findings,
            risk_level=risk_level,
            risk_details=risk_details,
        )
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.perf_counter() - started) * 1000)
        return ScanResult(
            input_target=job.input_target,
            url=job.url,
            host=job.host,
            port=job.port,
            scheme=job.scheme,
            ok=True,
            latency_ms=latency_ms,
            service=guess_service(job.port, "tcp"),
            transport="tcp",
            findings=[f"[INFO] 端口开放但非标准 HTTP 响应: {job.port}"],
            risk_level="info",
            risk_details=[
                build_risk("info", "发现开放端口", f"{job.host}:{job.port} 无法完成 HTTP 探测", "该端口可能是非 HTTP 服务，建议结合服务类型进一步人工确认")
            ],
            error=f"http_probe_failed: {exc}",
        )


def scan_targets(
    config: ScanConfig,
    writer: ArchiveWriter,
    observer: ScanObserver | None = None,
) -> dict:
    jobs = build_jobs(config.targets, config.ports)
    run_id, run_path = writer.prepare_run(config.targets)
    rate_limiter = RateLimiter(config.rate)
    total_jobs = len(jobs)
    if observer is None:
        observer = ConsoleObserver(total_jobs)
    progress = ProgressTracker(total=total_jobs)
    results: list[dict] = []
    started_at = time.perf_counter()
    queued_jobs = jobs[:]
    in_flight: dict[object, ScanJob] = {}
    seen_urls: set[str] = {job.url for job in jobs}
    host_page_counts: dict[str, int] = {}

    observer.on_start(total_jobs, run_id, run_path, config)
    try:
        with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
            while queued_jobs or in_flight:
                while queued_jobs and len(in_flight) < config.concurrency:
                    job = queued_jobs.pop(0)
                    rate_limiter.acquire()
                    future = executor.submit(fetch_http, job, config.timeout)
                    in_flight[future] = job

                if not in_flight:
                    continue

                done, _ = wait(set(in_flight.keys()), return_when=FIRST_COMPLETED)
                for future in done:
                    job = in_flight.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:  # noqa: BLE001
                        result = ScanResult(
                            input_target=job.input_target,
                            url=job.url,
                            host=job.host,
                            port=job.port,
                            scheme=job.scheme,
                            ok=False,
                            latency_ms=0,
                            error=f"worker_failed: {exc}",
                        )
                    progress.update(result)
                    snap = progress.snapshot()
                    observer.on_result(result, snap)
                    results.append(asdict(result))
                    for exposure in result.exposures or []:
                        exposure_result = build_exposure_result(result, exposure)
                        observer.on_result(exposure_result, snap)
                        results.append(asdict(exposure_result))

                    if result.ok and job.depth < config.crawl_depth:
                        host_key = f"{job.scheme}://{job.host}:{job.port}"
                        host_page_counts.setdefault(host_key, 0)
                        for discovered_url in result.discovered_urls or []:
                            if discovered_url in seen_urls:
                                continue
                            if host_page_counts[host_key] >= config.max_pages:
                                break
                            parts = urlsplit(discovered_url)
                            queued_jobs.append(
                                ScanJob(
                                    input_target=job.input_target,
                                    url=discovered_url,
                                    host=parts.hostname or job.host,
                                    port=parts.port or job.port,
                                    scheme=parts.scheme or job.scheme,
                                    path=urlunsplit(("", "", parts.path or "/", parts.query, "")),
                                    depth=job.depth + 1,
                                )
                            )
                            seen_urls.add(discovered_url)
                            host_page_counts[host_key] += 1
                            progress.total += 1
    finally:
        pass

    results.sort(key=lambda item: (not item["ok"], item["url"]))
    stats = progress.snapshot()
    duration_seconds = round(time.perf_counter() - started_at, 3)
    payload = {
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "archive_path": str(run_path),
        "target_count": len(config.targets),
        "config": {
            "ports": config.ports,
            "concurrency": config.concurrency,
            "rate": config.rate,
            "timeout": config.timeout,
            "crawl_depth": config.crawl_depth,
            "max_pages": config.max_pages,
        },
        "stats": {
            "total": stats["total"],
            "success": stats["success"],
            "failed": stats["failed"],
            "duration_seconds": duration_seconds,
            "throughput_per_second": round(stats["total"] / duration_seconds, 2)
            if duration_seconds > 0
            else 0.0,
        },
        "results": results,
    }
    writer.write(run_path, payload)
    observer.on_finish(payload)
    return payload
