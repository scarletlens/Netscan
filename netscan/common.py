from __future__ import annotations

from pathlib import Path

COMMON_WEB_PORTS = [
    80,
    81,
    88,
    443,
    591,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9000,
]


def load_targets(cli_targets: list[str], target_files: list[str]) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()

    for item in cli_targets:
        target = item.strip()
        if target and target not in seen:
            targets.append(target)
            seen.add(target)

    for filename in target_files:
        for line in Path(filename).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line not in seen:
                targets.append(line)
                seen.add(line)

    return targets


def parse_ports(raw: str) -> list[int]:
    if raw.strip().lower() == "common":
        return COMMON_WEB_PORTS.copy()
    ports: list[int] = []
    seen: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_raw, end_raw = chunk.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)
            if start > end:
                raise ValueError(f"invalid port range: {chunk}")
            for port in range(start, end + 1):
                if not 1 <= port <= 65535:
                    raise ValueError(f"invalid port: {port}")
                if port not in seen:
                    ports.append(port)
                    seen.add(port)
            continue
        port = int(chunk)
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid port: {port}")
        if port not in seen:
            ports.append(port)
            seen.add(port)
    return ports
