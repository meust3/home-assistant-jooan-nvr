"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .probes import DEFAULT_PORTS
from .scanner import run_scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jooan-discover",
        description=(
            "Discover and investigate JOOAN/EseeCloud NVR interfaces on directly connected "
            "RFC1918 LANs."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="run progressive LAN discovery")
    scan.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    scan.add_argument(
        "--network",
        action="append",
        dest="networks",
        help="scan a subset of an auto-detected direct RFC1918 network (repeatable)",
    )
    scan.add_argument("--max-hosts", type=int, default=1024)
    scan.add_argument("--include-virtual", action="store_true")
    scan.add_argument("--connect-timeout", type=float, default=0.45)
    scan.add_argument("--protocol-timeout", type=float, default=2.5)
    scan.add_argument("--concurrency", type=int, default=128)
    scan.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)))
    scan.add_argument(
        "--username", help="username to reuse if an interactive password prompt is needed"
    )
    scan.add_argument(
        "--prompt-credentials",
        action="store_true",
        help="prompt once (without echo) if the candidate requires authentication",
    )
    scan.add_argument(
        "--test-events",
        action="store_true",
        help="safely test ONVIF PullPoint with a one-minute transient subscription",
    )
    scan.add_argument("--verbose", action="store_true")
    return parser


def _ports(value: str) -> tuple[int, ...]:
    try:
        ports = tuple(sorted({int(item.strip()) for item in value.split(",") if item.strip()}))
    except ValueError as err:
        raise argparse.ArgumentTypeError("ports must be comma-separated integers") from err
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("ports must be in the range 1..65535")
    return ports


async def _run(args: argparse.Namespace) -> int:
    if args.command != "scan":
        _parser().print_help()
        return 2
    try:
        ports = _ports(args.ports)
        result = await run_scan(
            artifacts=args.artifacts,
            requested_networks=args.networks,
            include_virtual=args.include_virtual,
            max_hosts=args.max_hosts,
            ports=ports,
            connect_timeout=args.connect_timeout,
            protocol_timeout=args.protocol_timeout,
            concurrency=args.concurrency,
            username=args.username,
            prompt_credentials=args.prompt_credentials,
            test_events=args.test_events,
            progress=lambda message: print(f"[jooan-discovery] {message}", flush=True),
        )
    except (ValueError, argparse.ArgumentTypeError) as err:
        print(f"Safety/configuration error: {err}")
        return 2
    candidates = sorted(
        (host for host in result.hosts if host.score), key=lambda item: item.score, reverse=True
    )
    if candidates:
        print("\nCandidate results:")
        for host in candidates:
            print(f"  {host.address} — {host.score}% — {host.confidence}")
            for reason in host.score_reasons:
                print(f"    {reason}")
    else:
        print("\nNo JOOAN/EseeCloud candidate received a non-zero evidence score.")
    return 0


def main() -> None:
    args = _parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    raise SystemExit(asyncio.run(_run(args)))
