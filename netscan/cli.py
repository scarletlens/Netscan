from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from threading import Thread

from .common import load_targets, parse_ports
from .console import run_console
from .scanner import ArchiveWriter, NullObserver, ScanConfig, scan_targets
from .ui import DashboardObserver, run_dashboard, supports_dashboard


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="面向授权场景的资产探测与 HTTP 表面信息采集工具。",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="扫描目标并归档 HTTP 探测结果。",
    )
    scan_parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="目标主机名、IP 或完整 URL。可重复传入。",
    )
    scan_parser.add_argument(
        "--targets-file",
        action="append",
        default=[],
        help="目标文件路径，每行一个目标。可重复传入。",
    )
    scan_parser.add_argument(
        "--ports",
        default="common",
        help="逗号分隔的 TCP 端口列表，或使用 common 扫描常见 Web 端口。",
    )
    scan_parser.add_argument(
        "--crawl-depth",
        type=int,
        default=1,
        help="站内链接递归深度。默认：1。",
    )
    scan_parser.add_argument(
        "--max-pages",
        type=int,
        default=20,
        help="每个站点最多采集的页面数。默认：20。",
    )
    scan_parser.add_argument(
        "--concurrency",
        type=int,
        default=30,
        help="最大并发探测数。默认：30。",
    )
    scan_parser.add_argument(
        "--rate",
        type=float,
        default=15.0,
        help="每秒启动的最大探测数。默认：15。",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket 与 HTTP 超时时间，单位秒。默认：5。",
    )
    scan_parser.add_argument(
        "--archive-dir",
        default="archives",
        help="运行归档目录。默认：./archives。",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 输出最终结果摘要。",
    )
    scan_parser.add_argument(
        "--ui",
        choices=["auto", "text", "dashboard"],
        default="auto",
        help="界面模式：auto、text 或 dashboard。默认：auto。",
    )

    console_parser = subparsers.add_parser(
        "console",
        help="打开中文交互控制台。",
    )
    console_parser.add_argument(
        "--archive-dir",
        default="archives",
        help="运行归档目录。默认：./archives。",
    )

    return parser


def render_summary(summary: dict) -> None:
    run_id = summary["run_id"]
    total = summary["stats"]["total"]
    ok = summary["stats"]["success"]
    failed = summary["stats"]["failed"]
    archive_path = summary["archive_path"]

    print(f"任务编号: {run_id}")
    print(f"目标数: {summary['target_count']}  探测数: {total}")
    print(
        f"成功: {ok}  失败: {failed}  耗时: {summary['stats']['duration_seconds']} 秒  平均速率: {summary['stats']['throughput_per_second']}/秒"
    )
    print(f"归档目录: {archive_path}")

    top_results = [
        result
        for result in summary["results"]
        if result["ok"] and result.get("status")
    ][:10]
    if top_results:
        print("\n可访问端点:")
        for result in top_results:
            status = result.get("status") or "-"
            title = result.get("title") or "-"
            print(f"  {result['url']}  状态={status}  标题={title}")

    open_services = [
        result
        for result in summary["results"]
        if result["ok"]
    ][:20]
    if open_services:
        print("\n开放端口 / 服务:")
        for result in open_services:
            service = result.get("service") or "-"
            status = result.get("status")
            suffix = f"  HTTP状态={status}" if status else ""
            print(f"  {result['host']}:{result['port']}  服务={service}{suffix}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "console":
        return run_console(Path(args.archive_dir))

    if args.command != "scan":
        parser.error("unsupported command")

    try:
        targets = load_targets(args.target, args.targets_file)
        ports = parse_ports(args.ports)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not targets:
        print("error: at least one target is required", file=sys.stderr)
        return 2

    config = ScanConfig(
        targets=targets,
        ports=ports,
        concurrency=max(args.concurrency, 1),
        rate=max(args.rate, 0.1),
        timeout=max(args.timeout, 0.5),
        archive_dir=Path(args.archive_dir),
        crawl_depth=max(args.crawl_depth, 0),
        max_pages=max(args.max_pages, 1),
    )
    writer = ArchiveWriter(config.archive_dir)

    use_dashboard = (
        not args.json
        and (
            args.ui == "dashboard"
            or (args.ui == "auto" and supports_dashboard())
        )
    )

    if use_dashboard:
        observer = DashboardObserver()
        summary_holder: dict[str, dict] = {}

        def runner() -> None:
            summary_holder["summary"] = scan_targets(config, writer, observer)

        thread = Thread(target=runner, daemon=True)
        thread.start()
        try:
            run_dashboard(observer, summary_holder)
        except KeyboardInterrupt:
            pass
        thread.join()
        summary = summary_holder["summary"]
    else:
        summary = scan_targets(config, writer, NullObserver() if args.json else None)

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        render_summary(summary)

    return 0 if summary["stats"]["failed"] == 0 else 1
