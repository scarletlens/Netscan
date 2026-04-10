from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue

from .scanner import ScanConfig, ScanObserver, ScanResult


@dataclass(slots=True)
class UIEvent:
    kind: str
    payload: object


class DashboardObserver(ScanObserver):
    def __init__(self) -> None:
        self.events: Queue[UIEvent] = Queue()

    def on_start(self, total: int, run_id: str, run_path: Path, config: ScanConfig) -> None:
        self.events.put(
            UIEvent(
                "start",
                {
                    "total": total,
                    "run_id": run_id,
                    "run_path": str(run_path),
                    "config": config,
                },
            )
        )

    def on_result(self, result: ScanResult, stats: dict[str, int]) -> None:
        self.events.put(UIEvent("result", {"result": result, "stats": stats}))

    def on_finish(self, summary: dict) -> None:
        self.events.put(UIEvent("finish", summary))


def supports_dashboard() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") not in {"", "dumb"}


def run_dashboard(observer: DashboardObserver, summary_holder: dict[str, dict]) -> None:
    title = "Netscan 中文扫描面板"
    run_id = "-"
    archive_path = "-"
    total = 0
    completed = 0
    success = 0
    failed = 0
    latest: deque[ScanResult] = deque(maxlen=10)
    started_at = time.perf_counter()
    done = False
    config: ScanConfig | None = None

    try:
        sys.stdout.write("\033[?1049h\033[2J\033[H")
        sys.stdout.flush()
        while True:
            while True:
                try:
                    event = observer.events.get_nowait()
                except Empty:
                    break
                if event.kind == "start":
                    payload = event.payload
                    assert isinstance(payload, dict)
                    run_id = str(payload["run_id"])
                    archive_path = str(payload["run_path"])
                    total = int(payload["total"])
                    config = payload["config"]
                    started_at = time.perf_counter()
                elif event.kind == "result":
                    payload = event.payload
                    assert isinstance(payload, dict)
                    result = payload["result"]
                    stats = payload["stats"]
                    assert isinstance(result, ScanResult)
                    latest.appendleft(result)
                    completed = int(stats["completed"])
                    success = int(stats["success"])
                    failed = int(stats["failed"])
                elif event.kind == "finish":
                    assert isinstance(event.payload, dict)
                    summary_holder["summary"] = event.payload
                    done = True

            width, height = shutil.get_terminal_size((120, 32))
            elapsed = max(time.perf_counter() - started_at, 0.001)
            throughput = completed / elapsed
            progress = completed / total if total else 0.0
            bar_width = max(10, min(width - 20, 50))
            filled = int(bar_width * progress)
            bar = "█" * filled + "░" * (bar_width - filled)
            lines = [
                title,
                "=" * min(width, len(title)),
                f"任务编号: {run_id}",
                f"目标进度: [{bar}] {completed}/{total} ({progress * 100:5.1f}%)",
                f"成功: {success}    失败: {failed}    速率: {throughput:5.2f} 次/秒    耗时: {elapsed:5.1f} 秒",
            ]

            if config is not None:
                lines.append(
                    f"并发: {config.concurrency}    限速: {config.rate:.1f}/秒    超时: {config.timeout:.1f} 秒    端口: {','.join(map(str, config.ports))}"
                )
            lines.extend(
                [
                    f"归档目录: {archive_path}",
                    "",
                    "最近结果",
                    "-" * min(width, 48),
                ]
            )

            if latest:
                for item in latest:
                    status = str(item.status) if item.status is not None else "--"
                    title_text = item.title or "-"
                    error_text = item.error or ""
                    if not item.ok and error_text:
                        title_text = error_text
                    row = (
                        f"[{'OK' if item.ok else '失败'}] "
                        f"{item.url}  状态:{status}  延迟:{item.latency_ms}ms  {title_text}"
                    )
                    lines.append(row[: max(width - 1, 1)])
            else:
                lines.append("等待扫描结果...")

            lines.extend(
                [
                    "",
                    "提示: 按 Ctrl+C 可以提前结束显示，扫描结果仍会保存在归档目录。",
                ]
            )

            visible = lines[: max(height - 1, 1)]
            sys.stdout.write("\033[H\033[2J")
            sys.stdout.write("\n".join(visible))
            sys.stdout.flush()

            if done:
                time.sleep(0.25)
                break
            time.sleep(0.1)
    finally:
        sys.stdout.write("\033[?1049l")
        sys.stdout.flush()
