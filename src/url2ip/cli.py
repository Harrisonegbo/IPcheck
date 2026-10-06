"""Command-line interface for url2ip."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import (
    ResolutionError,
    TargetError,
    extract_hostname,
    parse_ports,
    resolve_hostname,
    scan_ports,
)


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not 0.1 <= number <= 10:
        raise argparse.ArgumentTypeError("must be between 0.1 and 10 seconds")
    return number


def _worker_count(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= number <= 64:
        raise argparse.ArgumentTypeError("must be between 1 and 64")
    return number


def _port_list(value: str) -> list[int]:
    try:
        return parse_ports(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="url2ip",
        description="Resolve a URL to IP addresses and optionally check TCP ports.",
        epilog=(
            "Only scan systems you own or have explicit permission to test. "
            "A port reported as closed_or_filtered may be blocked or unreachable."
        ),
    )
    parser.add_argument("target", help="HTTP(S) URL or hostname")
    parser.add_argument(
        "--ports",
        type=_port_list,
        metavar="LIST",
        help="optional TCP ports, e.g. 22,80,443 or 8000-8010 (max 256)",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=1.0,
        help="connection timeout in seconds, 0.1-10 (default: 1)",
    )
    parser.add_argument(
        "--workers",
        type=_worker_count,
        default=32,
        help="maximum concurrent connection checks, 1-64 (default: 32)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        hostname = extract_hostname(args.target)
        addresses = resolve_hostname(hostname)
    except (TargetError, ResolutionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        results = (
            scan_ports(addresses, args.ports, timeout=args.timeout, workers=args.workers)
            if args.ports
            else []
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "target": args.target,
                    "hostname": hostname,
                    "addresses": addresses,
                    "ports": [
                        {
                            "address": result.address,
                            "port": result.port,
                            "state": result.state,
                            "latency_ms": result.latency_ms,
                        }
                        for result in results
                    ],
                },
                indent=2,
            )
        )
        return 0

    print(f"Host: {hostname}")
    print(f"IP addresses: {', '.join(addresses)}")
    if results:
        print("\nTCP port scan:")
        for result in results:
            latency = (
                f" ({result.latency_ms:.2f} ms)"
                if result.latency_ms is not None
                else ""
            )
            print(f"  {result.address}:{result.port}  {result.state}{latency}")
    else:
        print("No ports scanned. Use --ports 22,80,443 to check specific ports.")
    return 0
