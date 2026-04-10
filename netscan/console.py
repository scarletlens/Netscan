from __future__ import annotations

import curses
import json
import shlex
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .common import COMMON_WEB_PORTS, parse_ports
from .scanner import ArchiveWriter, ScanConfig, scan_targets
from .ui import DashboardObserver


HELP_LINES = [
    "直接输入: example.com",
    "直接输入: 192.168.1.10",
    "直接输入: 192.168.1.10:8080",
    "直接输入: example.com 1-1024",
    "直接输入: 10.0.0.5 80,443,8000-9000",
    "直接输入: https://example.com/login",
    "自动检查: login/admin/swagger/actuator/.env",
    "/筛选 200",
    "/加载 latest",
    "/归档",
    "/帮助",
]

TABS = ["扫描", "结果", "风险", "归档"]


@dataclass
class ConsoleState:
    archive_dir: Path
    input_text: str = ""
    logs: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    filtered: list[dict] = field(default_factory=list)
    current_run: str | None = None
    current_archive: str | None = None
    scanning: bool = False
    scan_stats: dict[str, object] = field(default_factory=dict)
    active_tab: str = "扫描"
    status_message: str = "直接输入目标后回车开始扫描"

    def log(self, message: str) -> None:
        self.logs.append(message)
        self.logs = self.logs[-120:]
        self.status_message = message


def list_archives(archive_dir: Path) -> list[Path]:
    return sorted(archive_dir.glob("run-*"))


def load_summary(archive_dir: Path, run_id: str | None = None) -> dict | None:
    archives = list_archives(archive_dir)
    if not archives:
        return None
    target = archives[-1] if run_id in {None, "latest"} else archive_dir / run_id
    summary_path = target / "summary.json"
    if not summary_path.exists():
        return None
    return json.loads(summary_path.read_text(encoding="utf-8"))


def format_result(item: dict) -> str:
    status = item.get("status") or "--"
    title = item.get("title") or item.get("error") or "-"
    level = (item.get("risk_level") or "info").upper()
    findings = item.get("findings") or []
    findings_text = f" 风险:{'|'.join(findings[:2])}" if findings else ""
    return f"[{level}] {item['url']} 状态:{status} 延迟:{item['latency_ms']}ms 标题:{title}{findings_text}"


def truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if display_width(text) <= width:
        return text
    if width <= 1:
        return text[:1]
    trimmed = ""
    current = 0
    for char in text:
        char_w = char_width(char)
        if current + char_w > width - 1:
            break
        trimmed += char
        current += char_w
    return trimmed + "…"


def wrap_text(text: str, width: int) -> list[str]:
    if width <= 0:
        return [""]
    if not text:
        return [""]
    lines: list[str] = []
    current = ""
    current_width = 0
    for char in text:
        if char == "\n":
            lines.append(current)
            current = ""
            current_width = 0
            continue
        char_w = char_width(char)
        if current and current_width + char_w > width:
            lines.append(current)
            current = char
            current_width = char_w
            continue
        current += char
        current_width += char_w
    if current or not lines:
        lines.append(current)
    return lines


def char_width(char: str) -> int:
    if unicodedata.combining(char):
        return 0
    return 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1


def display_width(text: str) -> int:
    return sum(char_width(char) for char in text)


def draw_wrapped_text(
    stdscr: curses.window,
    y: int,
    x: int,
    width: int,
    height: int,
    text: str,
    attr: int = 0,
) -> int:
    lines = wrap_text(text, width)
    written = 0
    for idx, line in enumerate(lines):
        if idx >= height:
            break
        safe_addnstr(stdscr, y + idx, x, line, width, attr)
        written += 1
    return written


def safe_addnstr(
    stdscr: curses.window,
    y: int,
    x: int,
    text: str,
    width: int,
    attr: int = 0,
) -> None:
    if width <= 0 or y < 0 or x < 0:
        return
    try:
        stdscr.addnstr(y, x, text, width, attr)
    except curses.error:
        return


def init_theme() -> dict[str, int]:
    theme = {
        "frame": curses.A_DIM,
        "title": curses.A_BOLD,
        "muted": curses.A_DIM,
        "accent": curses.A_BOLD,
        "good": curses.A_BOLD,
        "warn": curses.A_BOLD,
        "bad": curses.A_BOLD,
        "tab_active": curses.A_REVERSE | curses.A_BOLD,
        "tab_idle": curses.A_DIM,
    }
    if not curses.has_colors():
        return theme
    curses.start_color()
    try:
        curses.use_default_colors()
    except curses.error:
        pass
    curses.init_pair(1, 114, -1)
    curses.init_pair(2, 186, -1)
    curses.init_pair(3, 244, -1)
    curses.init_pair(4, 203, -1)
    curses.init_pair(5, 39, -1)
    curses.init_pair(6, 177, -1)
    theme.update(
        {
            "frame": curses.color_pair(3),
            "title": curses.color_pair(2) | curses.A_BOLD,
            "muted": curses.color_pair(3),
            "accent": curses.color_pair(1) | curses.A_BOLD,
            "good": curses.color_pair(1) | curses.A_BOLD,
            "warn": curses.color_pair(2) | curses.A_BOLD,
            "bad": curses.color_pair(4) | curses.A_BOLD,
            "info": curses.color_pair(5) | curses.A_BOLD,
            "magenta": curses.color_pair(6) | curses.A_BOLD,
            "tab_active": curses.color_pair(1) | curses.A_BOLD,
            "tab_idle": curses.color_pair(3),
        }
    )
    return theme


def draw_box(
    stdscr: curses.window,
    y: int,
    x: int,
    h: int,
    w: int,
    title: str,
    theme: dict[str, int],
) -> None:
    if h < 3 or w < 4:
        return
    right = x + w - 1
    bottom = y + h - 1
    try:
        stdscr.addch(y, x, curses.ACS_ULCORNER, theme["frame"])
        stdscr.addch(y, right, curses.ACS_URCORNER, theme["frame"])
        stdscr.addch(bottom, x, curses.ACS_LLCORNER, theme["frame"])
        stdscr.addch(bottom, right, curses.ACS_LRCORNER, theme["frame"])
        stdscr.hline(y, x + 1, curses.ACS_HLINE, w - 2, theme["frame"])
        stdscr.hline(bottom, x + 1, curses.ACS_HLINE, w - 2, theme["frame"])
        stdscr.vline(y + 1, x, curses.ACS_VLINE, h - 2, theme["frame"])
        stdscr.vline(y + 1, right, curses.ACS_VLINE, h - 2, theme["frame"])
    except curses.error:
        return
    safe_addnstr(stdscr, y, x + 2, f" {title} ", w - 4, theme["title"])


def draw_kv_line(
    stdscr: curses.window,
    y: int,
    x: int,
    width: int,
    label: str,
    value: str,
    theme: dict[str, int],
    value_attr: int | None = None,
) -> None:
    value_attr = theme["accent"] if value_attr is None else value_attr
    safe_addnstr(stdscr, y, x, f"{label} ", width, theme["muted"])
    offset = min(len(label) + 1, width)
    draw_wrapped_text(stdscr, y, x + offset, max(width - offset, 0), 2, value, value_attr)


def summarize_findings(results: list[dict]) -> list[str]:
    counts: dict[str, int] = {}
    for item in results:
        for finding in item.get("findings") or []:
            counts[finding] = counts.get(finding, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [f"{name}  x{count}" for name, count in ranked[:8]]


def archive_rows(state: ConsoleState) -> list[str]:
    rows: list[str] = []
    for archive in reversed(list_archives(state.archive_dir)[-10:]):
        summary = load_summary(state.archive_dir, archive.name)
        if not summary:
            continue
        rows.append(
            f"{summary['run_id']}  成功:{summary['stats']['success']}  失败:{summary['stats']['failed']}  目标:{summary['target_count']}"
        )
    return rows or ["暂无归档"]


def risk_rows(state: ConsoleState) -> list[str]:
    rows: list[str] = []
    source = state.filtered or state.results
    for item in source:
        details = item.get("risk_details") or []
        for detail in details:
            rows.append(
                f"[{detail['severity'].upper()}] {detail['title']} | 证据: {detail['evidence']} | 建议: {detail['suggestion']}"
            )
    if rows:
        return rows
    return ["暂无风险提示"]


def result_rows(state: ConsoleState) -> list[str]:
    rows = [format_result(item) for item in (state.filtered or state.results)]
    return rows or ["暂无结果，先输入目标开始扫描。"]


def recent_probe_rows(state: ConsoleState) -> list[str]:
    if state.results:
        return [format_result(item) for item in state.results[:8]]
    return state.logs[-8:] or ["等待任务启动..."]


def render_main_panel(stdscr: curses.window, state: ConsoleState, y: int, h: int, w: int, theme: dict[str, int]) -> None:
    title_map = {
        "扫描": "扫描进度",
        "结果": "扫描结果",
        "风险": "风险视图",
        "归档": "历史归档",
    }
    draw_box(stdscr, y, 2, h, w, title_map[state.active_tab], theme)
    visible_rows = max(h - 3, 1)
    if state.active_tab == "扫描":
        total = int(state.scan_stats.get("total", 0) or 0)
        completed = int((state.scan_stats.get("success", 0) or 0) + (state.scan_stats.get("failed", 0) or 0))
        safe_addnstr(stdscr, y + 1, 4, "当前进度", w - 6, theme["warn"])
        draw_progress_bar(stdscr, y + 2, 4, max(w - 8, 10), completed, total, theme)
        safe_addnstr(stdscr, y + 3, 4, f"{completed}/{total or 0}  成功={state.scan_stats.get('success', 0)}  失败={state.scan_stats.get('failed', 0)}", w - 6, theme["muted"])
        row_y = y + 5
        max_height = max(visible_rows - 4, 1)
        for line in recent_probe_rows(state):
            used = draw_wrapped_text(stdscr, row_y, 4, w - 6, max_height - (row_y - (y + 5)), line, theme["muted"])
            row_y += max(used, 1)
            if row_y >= y + 5 + max_height:
                break
        return
    rows = result_rows(state) if state.active_tab == "结果" else risk_rows(state) if state.active_tab == "风险" else archive_rows(state)
    attr = theme["good"] if state.active_tab == "结果" else theme["bad"] if state.active_tab == "风险" else theme["muted"]
    row_y = y + 1
    end_y = y + 1 + visible_rows
    for line in rows:
        used = draw_wrapped_text(stdscr, row_y, 4, w - 6, end_y - row_y, line, attr)
        row_y += max(used, 1)
        if row_y >= end_y:
            break


def render_side_panel(stdscr: curses.window, state: ConsoleState, y: int, h: int, x: int, w: int, theme: dict[str, int]) -> None:
    draw_box(stdscr, y, x, h, w, "情报面板", theme)
    focus = state.filtered[0] if state.filtered else (state.results[0] if state.results else None)
    if state.active_tab == "归档":
        safe_addnstr(stdscr, y + 1, x + 2, "使用 /加载 latest 或 /加载 run-编号", w - 4, theme["accent"])
        row_y = y + 2
        end_y = y + h - 1
        for line in state.logs[-(h - 4):] or ["归档操作日志为空"]:
            used = draw_wrapped_text(stdscr, row_y, x + 2, w - 4, end_y - row_y, line, theme["muted"])
            row_y += max(used, 1)
            if row_y >= end_y:
                break
        return
    if not focus:
        safe_addnstr(stdscr, y + 1, x + 2, "等待载入结果", w - 4, theme["muted"])
        return
    draw_kv_line(stdscr, y + 1, x + 2, w - 4, "URL", focus.get("url", "-"), theme, theme["info"])
    draw_kv_line(stdscr, y + 2, x + 2, w - 4, "状态码", str(focus.get("status") or "--"), theme, theme["good"])
    draw_kv_line(stdscr, y + 3, x + 2, w - 4, "级别", str(focus.get("risk_level") or "info").upper(), theme, theme["bad"] if focus.get("risk_level") in {"high", "medium"} else theme["warn"])
    draw_kv_line(stdscr, y + 4, x + 2, w - 4, "标题", focus.get("title") or "-", theme)
    draw_kv_line(stdscr, y + 5, x + 2, w - 4, "类型", focus.get("content_type") or "-", theme)
    draw_kv_line(stdscr, y + 6, x + 2, w - 4, "大小", str(focus.get("content_length") or "-"), theme)
    draw_kv_line(stdscr, y + 7, x + 2, w - 4, "重定向", focus.get("redirect_location") or "-", theme)
    draw_kv_line(stdscr, y + 8, x + 2, w - 4, "方法", ",".join(focus.get("methods") or []) or "-", theme, theme["magenta"])
    safe_addnstr(stdscr, y + 10, x + 2, "Cookie", w - 4, theme["warn"])
    cookie_rows = focus.get("cookies") or ["未发现 Set-Cookie"]
    row_y = y + 11
    for row in cookie_rows[:2]:
        used = draw_wrapped_text(stdscr, row_y, x + 2, w - 4, 2, row, theme["muted"])
        row_y += max(used, 1)
    safe_addnstr(stdscr, y + 14, x + 2, "页面信号", w - 4, theme["warn"])
    signal_rows = focus.get("page_signals") or ["未识别到登录页/后台页信号"]
    row_y = y + 15
    for row in signal_rows[:2]:
        used = draw_wrapped_text(stdscr, row_y, x + 2, w - 4, 2, row, theme["info"])
        row_y += max(used, 1)
    safe_addnstr(stdscr, y + 18, x + 2, "线索", w - 4, theme["warn"])
    exposure_rows = focus.get("exposures") or ["未发现额外暴露路径"]
    row_y = y + 19
    end_y = y + h - 1
    for row in exposure_rows:
        used = draw_wrapped_text(stdscr, row_y, x + 2, w - 4, end_y - row_y, row, theme["bad"] if "200" in row else theme["muted"])
        row_y += max(used, 1)
        if row_y >= end_y:
            break


def draw_tabs(stdscr: curses.window, y: int, x: int, width: int, state: ConsoleState, theme: dict[str, int]) -> None:
    draw_box(stdscr, y, x, 3, width, "标签页  Tab/Shift+Tab 切换", theme)
    cursor = x + 2
    for idx, tab in enumerate(TABS, start=1):
        label = f"({idx}) {tab}"
        attr = theme["tab_active"] if state.active_tab == tab else theme["tab_idle"]
        safe_addnstr(stdscr, y + 1, cursor, label, max(width - (cursor - x) - 2, 0), attr)
        cursor += len(label) + 3


def draw_progress_bar(
    stdscr: curses.window,
    y: int,
    x: int,
    width: int,
    completed: int,
    total: int,
    theme: dict[str, int],
) -> None:
    width = max(width, 10)
    total = max(total, 1)
    filled = min(width, int(width * (completed / total)))
    safe_addnstr(stdscr, y, x, "█" * filled, width, theme["accent"])
    if filled < width:
        safe_addnstr(stdscr, y, x + filled, "░" * (width - filled), width - filled, theme["frame"])


def apply_filter(results: list[dict], keyword: str) -> list[dict]:
    query = keyword.strip().lower()
    if not query:
        return results
    matched: list[dict] = []
    for item in results:
        haystacks = [
            str(item.get("url", "")),
            str(item.get("title", "")),
            str(item.get("status", "")),
            str(item.get("server", "")),
            str(item.get("error", "")),
            " ".join(item.get("findings") or []),
        ]
        if any(query in text.lower() for text in haystacks):
            matched.append(item)
    return matched


def parse_scan_command(tokens: list[str], archive_dir: Path) -> ScanConfig:
    if len(tokens) < 2:
        raise ValueError("scan 命令至少需要一个目标，例如: scan example.com")
    target = tokens[1]
    options = {
        "ports": "common",
        "concurrency": "30",
        "rate": "15",
        "timeout": "5",
        "crawl_depth": "1",
        "max_pages": "20",
    }
    for token in tokens[2:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        options[key] = value
    return ScanConfig(
        targets=[target],
        ports=parse_ports(options["ports"]),
        concurrency=max(int(options["concurrency"]), 1),
        rate=max(float(options["rate"]), 0.1),
        timeout=max(float(options["timeout"]), 0.5),
        archive_dir=archive_dir,
        crawl_depth=max(int(options["crawl_depth"]), 0),
        max_pages=max(int(options["max_pages"]), 1),
    )


def parse_direct_target_input(raw: str, archive_dir: Path) -> ScanConfig:
    target = raw.strip()
    if not target:
        raise ValueError("请输入域名、IP、IP:端口 或 URL")

    parts = target.split()
    port_expr = None
    if len(parts) >= 2:
        target = parts[0]
        port_expr = parts[1]

    if "://" in target:
        return ScanConfig(
            targets=[target],
            ports=parse_ports(port_expr) if port_expr else COMMON_WEB_PORTS.copy(),
            concurrency=30,
            rate=15.0,
            timeout=5.0,
            archive_dir=archive_dir,
            crawl_depth=1,
            max_pages=20,
        )

    host = target
    ports = [80, 443]
    if target.count(":") == 1:
        maybe_host, maybe_port = target.rsplit(":", 1)
        if maybe_port.isdigit():
            port = int(maybe_port)
            if not 1 <= port <= 65535:
                raise ValueError("端口必须在 1 到 65535 之间")
            host = maybe_host.strip()
            ports = [port]

    if not host:
        raise ValueError("目标不能为空")

    return ScanConfig(
        targets=[host],
        ports=parse_ports(port_expr) if port_expr else (COMMON_WEB_PORTS.copy() if ports == [80, 443] else ports),
        concurrency=30,
        rate=15.0,
        timeout=5.0,
        archive_dir=archive_dir,
        crawl_depth=1,
        max_pages=20,
    )


def run_scan_in_background(state: ConsoleState, config: ScanConfig) -> None:
    observer = DashboardObserver()
    writer = ArchiveWriter(config.archive_dir)

    def runner() -> None:
        try:
            summary = scan_targets(config, writer, observer)
            state.current_run = summary["run_id"]
            state.current_archive = summary["archive_path"]
            state.results = summary["results"]
            state.filtered = summary["results"]
            state.scan_stats = summary["stats"]
            state.log(f"扫描完成: {summary['run_id']} 成功 {summary['stats']['success']} 条")
        except Exception as exc:  # noqa: BLE001
            state.log(f"扫描失败: {exc}")
        finally:
            state.scanning = False

    state.scanning = True
    state.log(f"开始扫描目标: {config.targets[0]}")
    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    def consume() -> None:
        while state.scanning:
            while not observer.events.empty():
                event = observer.events.get()
                if event.kind == "start":
                    payload = event.payload
                    assert isinstance(payload, dict)
                    state.current_run = str(payload["run_id"])
                    state.current_archive = str(payload["run_path"])
                elif event.kind == "result":
                    payload = event.payload
                    assert isinstance(payload, dict)
                    result = payload["result"]
                    stats = payload["stats"]
                    state.scan_stats = stats
                    if hasattr(result, "url"):
                        state.log(f"结果: {result.url}")
                time.sleep(0.01)
            time.sleep(0.05)

    threading.Thread(target=consume, daemon=True).start()


def draw_console(stdscr: curses.window, state: ConsoleState) -> None:
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    theme = init_theme()
    stdscr.timeout(100)
    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()

        if height < 24 or width < 100:
            safe_addnstr(stdscr, 1, 2, "终端尺寸过小，请至少使用 100x24。", width - 4, theme["bad"])
            stdscr.refresh()
            key = stdscr.getch()
            if key == 27:
                return
            continue

        safe_addnstr(stdscr, 0, 2, "Netscan 中文控制台  (v0.1.0)", width - 4, theme["muted"])

        top_y = 2
        top_h = 8
        left_w = width // 2 - 2
        right_x = left_w + 3
        right_w = width - right_x - 2

        draw_box(stdscr, top_y, 2, top_h, left_w, "命令面板", theme)
        safe_addnstr(stdscr, top_y + 1, 4, "直接输入目标即可扫描", left_w - 6, theme["accent"])
        for idx, line in enumerate(HELP_LINES[: top_h - 3], start=2):
            safe_addnstr(stdscr, top_y + idx, 4, truncate(line, left_w - 6), left_w - 6, theme["muted"])

        draw_box(stdscr, top_y, right_x, top_h, right_w, "运行概览", theme)
        draw_kv_line(stdscr, top_y + 1, right_x + 2, right_w - 4, "运行", state.current_run or "-", theme, theme["info"])
        draw_kv_line(stdscr, top_y + 2, right_x + 2, right_w - 4, "状态", "扫描中" if state.scanning else "空闲", theme, theme["good"] if state.scanning else theme["muted"])
        draw_kv_line(stdscr, top_y + 3, right_x + 2, right_w - 4, "归档", truncate(Path(state.current_archive).name if state.current_archive else "-", right_w - 12), theme)
        draw_kv_line(
            stdscr,
            top_y + 4,
            right_x + 2,
            right_w - 4,
            "统计",
            f"总 {state.scan_stats.get('total', 0)} / 成功 {state.scan_stats.get('success', 0)} / 失败 {state.scan_stats.get('failed', 0)}",
            theme,
        )
        draw_kv_line(
            stdscr,
            top_y + 5,
            right_x + 2,
            right_w - 4,
            "速率",
            f"{state.scan_stats.get('throughput_per_second', 0)} 次/秒",
            theme,
            theme["magenta"],
        )

        tabs_y = top_y + top_h + 1
        draw_tabs(stdscr, tabs_y, 2, width - 4, state, theme)

        body_y = tabs_y + 4
        body_h = height - body_y - 5
        body_left_w = int((width - 6) * 0.68)
        body_right_x = 2 + body_left_w + 1
        body_right_w = width - body_right_x - 2

        render_main_panel(stdscr, state, body_y, body_h, body_left_w, theme)
        render_side_panel(stdscr, state, body_y, body_h, body_right_x, body_right_w, theme)

        input_y = height - 3
        draw_box(stdscr, input_y, 2, 3, width - 4, "输入框  ESC 退出", theme)
        prompt = "目标>>> "
        safe_addnstr(stdscr, input_y + 1, 4, prompt, width - 8, theme["accent"])
        safe_addnstr(stdscr, input_y + 1, 4 + len(prompt), state.input_text, width - 8 - len(prompt), theme["title"])
        stdscr.move(input_y + 1, min(4 + len(prompt) + len(state.input_text), width - 3))
        stdscr.refresh()

        key = stdscr.getch()
        if key == -1:
            continue
        if key == 9:
            current = TABS.index(state.active_tab)
            state.active_tab = TABS[(current + 1) % len(TABS)]
            state.log(f"切换到标签页: {state.active_tab}")
            continue
        if key == curses.KEY_BTAB:
            current = TABS.index(state.active_tab)
            state.active_tab = TABS[(current - 1) % len(TABS)]
            state.log(f"切换到标签页: {state.active_tab}")
            continue
        if key in (10, 13):
            command = state.input_text.strip()
            state.input_text = ""
            if handle_command(state, command):
                return
            continue
        if key in (curses.KEY_BACKSPACE, 127, 8):
            state.input_text = state.input_text[:-1]
            continue
        if key == 27:
            return
        if 32 <= key <= 126:
            state.input_text += chr(key)


def handle_command(state: ConsoleState, command: str) -> bool:
    if not command:
        return False
    state.log(f"> {command}")
    if not command.startswith("/"):
        if state.scanning:
            state.log("已有扫描在运行，请稍候")
            return False
        config = parse_direct_target_input(command, state.archive_dir)
        state.active_tab = "扫描"
        run_scan_in_background(state, config)
        return False

    tokens = shlex.split(command)
    name = tokens[0].lower().lstrip("/")

    if name == "quit":
        return True
    if name in {"help", "帮助"}:
        state.active_tab = "扫描"
        state.log("直接输入域名、IP、IP:端口 或 URL 即可开始扫描")
        state.log("高级功能: /筛选 关键字  /加载 latest  /归档  /退出")
        return False
    if name in {"archives", "归档"}:
        state.active_tab = "归档"
        archives = list_archives(state.archive_dir)
        if not archives:
            state.log("暂无归档")
        else:
            for archive in archives[-8:]:
                state.log(f"归档: {archive.name}")
        return False
    if name in {"load", "加载"}:
        state.active_tab = "归档"
        run_id = tokens[1] if len(tokens) > 1 else "latest"
        summary = load_summary(state.archive_dir, run_id)
        if not summary:
            state.log(f"未找到归档: {run_id}")
            return False
        state.current_run = summary["run_id"]
        state.current_archive = summary["archive_path"]
        state.results = summary["results"]
        state.filtered = summary["results"]
        state.scan_stats = summary["stats"]
        state.log(f"已加载归档: {summary['run_id']}")
        return False
    if name in {"find", "筛选"}:
        state.active_tab = "结果"
        keyword = " ".join(tokens[1:]) if len(tokens) > 1 else ""
        state.filtered = apply_filter(state.results, keyword)
        state.log(f"筛选结果: {len(state.filtered)} 条")
        return False
    if name in {"scan"}:
        state.active_tab = "扫描"
        if state.scanning:
            state.log("已有扫描在运行，请稍候")
            return False
        config = parse_scan_command(tokens, state.archive_dir)
        run_scan_in_background(state, config)
        return False
    if name in {"quit", "退出"}:
        return True

    state.log(f"无法识别输入: {name}")
    return False


def run_console(archive_dir: Path) -> int:
    state = ConsoleState(archive_dir=archive_dir)

    def wrapped(stdscr: curses.window) -> None:
        draw_console(stdscr, state)

    curses.wrapper(wrapped)
    return 0
