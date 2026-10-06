"""URL parsing, DNS resolution, and bounded TCP connect scanning."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_CONNECTION_ATTEMPTS = 512


class TargetError(ValueError):
    """Raised when a target is not a valid URL or hostname."""


class ResolutionError(OSError):
    """Raised when DNS resolution fails."""


@dataclass(frozen=True)
class ScanResult:
    address: str
    port: int
    state: str
    latency_ms: float | None = None


def extract_hostname(target: str) -> str:
    """Return the hostname from a URL or a bare hostname/IP address."""
    value = target.strip()
    if not value or any(ord(character) < 32 for character in value):
        raise TargetError("Enter a valid URL or hostname.")

    has_scheme = "://" in value
    if has_scheme:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise TargetError(f"Invalid URL: {exc}") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise TargetError("Only http and https URLs are supported.")
        if parsed.username is not None or parsed.password is not None:
            raise TargetError("URLs containing username or password are not supported.")
    else:
        try:
            parsed = urlsplit(f"//{value}")
        except ValueError as exc:
            raise TargetError(f"Invalid host: {exc}") from exc

    try:
        hostname = parsed.hostname
        parsed.port  # Validate that an optional URL port is numeric and in range.
    except ValueError as exc:
        raise TargetError(f"Invalid host or port: {exc}") from exc

    if not hostname:
        raise TargetError("The URL must include a hostname.")
    return hostname


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to unique IP addresses, preserving system order."""
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResolutionError(f"Could not resolve {hostname}: {exc}") from exc

    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise ResolutionError(f"No IP addresses found for {hostname}.")
    return addresses


def parse_ports(specification: str, *, max_ports: int = 256) -> list[int]:
    """Parse comma-separated ports and ranges such as ``22,80,8000-8010``."""
    if not specification.strip():
        raise ValueError("Provide at least one port.")

    ports: list[int] = []
    seen: set[int] = set()
    for part in specification.split(","):
        item = part.strip()
        if not item:
            raise ValueError("Port lists cannot contain empty entries.")
        bounds = item.split("-")
        if len(bounds) > 2:
            raise ValueError(f"Invalid port or range: {item}")
        try:
            start = int(bounds[0])
            end = int(bounds[-1])
        except ValueError as exc:
            raise ValueError(f"Invalid port or range: {item}") from exc
        if not 1 <= start <= 65535 or not 1 <= end <= 65535:
            raise ValueError("Ports must be between 1 and 65535.")
        if start > end:
            raise ValueError(f"Port range must be ascending: {item}")
        for port in range(start, end + 1):
            if port not in seen:
                seen.add(port)
                ports.append(port)
                if len(ports) > max_ports:
                    raise ValueError(f"Limit scans to {max_ports} unique ports per run.")
    return ports


def _scan_one(address: str, port: int, timeout: float) -> ScanResult:
    started = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000
            return ScanResult(address, port, "open", round(elapsed, 2))
    except OSError:
        return ScanResult(address, port, "closed_or_filtered")


def scan_ports(
    addresses: list[str],
    ports: list[int],
    *,
    timeout: float = 1.0,
    workers: int = 32,
) -> list[ScanResult]:
    """Check TCP connect availability for each address/port pair."""
    if not addresses:
        raise ValueError("At least one resolved address is required.")
    if not ports:
        raise ValueError("At least one port is required.")
    if not 0.1 <= timeout <= 10:
        raise ValueError("Timeout must be between 0.1 and 10 seconds.")
    if not 1 <= workers <= 64:
        raise ValueError("Workers must be between 1 and 64.")

    jobs = [(address, port) for address in addresses for port in ports]
    if len(jobs) > MAX_CONNECTION_ATTEMPTS:
        raise ValueError(
            f"Limit scans to {MAX_CONNECTION_ATTEMPTS} address/port checks per run."
        )
    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as executor:
        results = list(
            executor.map(
                lambda job: _scan_one(job[0], job[1], timeout),
                jobs,
            )
        )
    return results
