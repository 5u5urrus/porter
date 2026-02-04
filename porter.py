#!/usr/bin/env python3
"""
Porter - fast, clean TCP connect port scanner (Windows/macOS/Linux)
Author: Vahe Demirkhanyan
"""

import argparse
import asyncio
import contextlib
import errno
import ipaddress
import os
import socket
import sys
import time
from typing import Dict, List, Set, Tuple


POPULAR_PORTS = [
    80, 443, 22, 3389, 445, 1433, 3306, 53, 25, 110, 143, 995, 993, 587, 465,
    21, 23, 8080, 8443, 6379, 27017, 9200, 5000, 8000, 8888, 5900, 5901, 389,
    636, 1521, 2049, 111, 139, 135, 7001, 8081, 8082, 15672, 5672, 11211, 514,
    853, 8530, 4369, 5432, 27018, 27019, 25565
]


def expand_targets(arg: str) -> List[str]:
    try:
        net = ipaddress.ip_network(arg, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [arg.strip()]


def _expand_ipv4_last_octet_range(token: str) -> List[str]:
    """
    Expand IPv4 short-range form: a.b.c.X-Y
    Example: 1.1.1.10-15 -> [1.1.1.10, ..., 1.1.1.15]
    If token doesn't match that pattern, return [token] unchanged.
    """
    s = token.strip()
    if not s:
        return []

    # must be IPv4-ish with exactly one dash in the last octet section
    # and exactly 3 dots total
    if s.count(".") != 3 or "-" not in s:
        return [s]

    left, right = s.rsplit(".", 1)
    if "-" not in right:
        return [s]

    a_str, b_str = right.split("-", 1)
    if not (a_str.isdigit() and b_str.isdigit()):
        return [s]

    try:
        base_ip = ipaddress.IPv4Address(f"{left}.0")
    except Exception:
        return [s]

    a = int(a_str)
    b = int(b_str)
    if not (0 <= a <= 255 and 0 <= b <= 255):
        return [s]
    if a > b:
        a, b = b, a

    # validate left part is 3 octets
    parts = left.split(".")
    if len(parts) != 3 or any((not p.isdigit()) or not (0 <= int(p) <= 255) for p in parts):
        return [s]

    return [f"{left}.{i}" for i in range(a, b + 1)]


def parse_target_arg(arg: str) -> List[str]:
    """
    Accepts:
      - single host / IP
      - CIDR
      - comma-separated list of the above
      - IPv4 last-octet ranges like 1.1.1.10-15 (and can be mixed with commas)

    Returns deduped targets preserving order.
    """
    out: List[str] = []
    for raw in arg.split(","):
        tok = raw.strip()
        if not tok:
            continue

        # CIDR expansion (existing behavior)
        if "/" in tok:
            out.extend(expand_targets(tok))
            continue

        # IPv4 last-octet ranges like a.b.c.X-Y
        expanded = _expand_ipv4_last_octet_range(tok)
        out.extend(expanded)

    return list(dict.fromkeys(out))


def parse_ports(spec: str) -> List[int]:
    if spec == "popular":
        return list(dict.fromkeys(POPULAR_PORTS))
    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def order_ports(ports: List[int]) -> List[int]:
    rank = {p: i for i, p in enumerate(POPULAR_PORTS)}
    return sorted(ports, key=lambda p: (0, rank[p]) if p in rank else (1, p))


class Resolver:
    def __init__(self) -> None:
        self._cache: Dict[str, List[str]] = {}

    async def resolve(self, target: str) -> List[str]:
        if target in self._cache:
            return self._cache[target]

        try:
            ipaddress.ip_address(target)
            self._cache[target] = [target]
            return self._cache[target]
        except ValueError:
            pass

        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                target,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_ADDRCONFIG,
            )
            v4, v6 = [], []
            for fam, _typ, _pro, _can, sa in infos:
                ip = sa[0]
                if fam == socket.AF_INET:
                    v4.append(ip)
                elif fam == socket.AF_INET6:
                    v6.append(ip)
            ips = list(dict.fromkeys(v4 + v6))  # v4 then v6
        except socket.gaierror:
            ips = []

        self._cache[target] = ips
        return ips


def _sock_family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _jitter_seconds(ip: str, port: int) -> float:
    x = 0
    for ch in ip:
        x = ((x << 5) - x) + ord(ch)
        x &= 0xFFFFFFFF
    x ^= (port * 2654435761) & 0xFFFFFFFF
    return (x % 2001) / 1_000_000.0


async def connect_probe(ip: str, port: int, timeout_s: float) -> str:
    loop = asyncio.get_running_loop()
    fam = _sock_family(ip)
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.setblocking(False)

    try:
        await asyncio.sleep(_jitter_seconds(ip, port))
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=timeout_s)
        return "open"
    except asyncio.TimeoutError:
        return "timeout"
    except (ConnectionRefusedError, OSError) as e:
        code = getattr(e, "errno", None)
        if isinstance(e, ConnectionRefusedError) or code in {errno.ECONNREFUSED, 10061}:
            return "closed"
        return "filtered"
    finally:
        with contextlib.suppress(Exception):
            sock.close()


class Scanner:
    def __init__(self, targets: List[str], ports: List[int],
                 conc: int = 300, tfast: float = 0.30, tslow: float = 1.00,
                 retry: bool = True, quiet: bool = False):
        self.targets = targets
        self.ports = order_ports(ports)

        self.conc = max(1, min(int(conc), 1024))

        self.tfast = float(tfast)
        self.tslow = float(tslow)
        self.retry = bool(retry)
        self.quiet = bool(quiet)

        self.resolver = Resolver()

        self.dns_failed: Set[int] = set()
        self.ips_by_target: List[List[str]] = [[] for _ in targets]

        self.opens_by_target: List[Set[int]] = [set() for _ in targets]
        self.timeouts: Set[Tuple[int, str, int]] = set()

    async def resolve_all(self):
        for i, t in enumerate(self.targets):
            ips = await self.resolver.resolve(t)
            if not ips:
                await asyncio.sleep(0.1)
                ips = await self.resolver.resolve(t)
            if not ips:
                self.dns_failed.add(i)
                self.ips_by_target[i] = []
            else:
                self.ips_by_target[i] = ips

    async def _run_pass(self, timeout_s: float, pass_id: int):
        q: asyncio.Queue = asyncio.Queue()

        for port in self.ports:
            for ti, t in enumerate(self.targets):
                if ti in self.dns_failed:
                    continue
                for ip in self.ips_by_target[ti]:
                    q.put_nowait((ti, t, ip, port))

        for _ in range(self.conc):
            q.put_nowait(None)

        async def worker():
            while True:
                item = await q.get()
                if item is None:
                    q.task_done()
                    return
                ti, t, ip, port = item
                try:
                    state = await connect_probe(ip, port, timeout_s)
                    if state == "open":
                        if port not in self.opens_by_target[ti]:
                            self.opens_by_target[ti].add(port)
                            if not self.quiet:
                                print(f"{t}:{port} open")
                    elif state == "timeout":
                        if self.retry and pass_id == 1:
                            self.timeouts.add((ti, ip, port))
                finally:
                    q.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.conc)]
        await q.join()

        for w in workers:
            w.cancel()
        for w in workers:
            with contextlib.suppress(asyncio.CancelledError):
                await w

    async def run(self):
        await self.resolve_all()
        await self._run_pass(self.tfast, pass_id=1)

        if not self.retry or not self.timeouts:
            return

        q: asyncio.Queue = asyncio.Queue()
        for (ti, ip, port) in self.timeouts:
            t = self.targets[ti]
            q.put_nowait((ti, t, ip, port))

        for _ in range(self.conc):
            q.put_nowait(None)

        async def worker2():
            while True:
                item = await q.get()
                if item is None:
                    q.task_done()
                    return
                ti, t, ip, port = item
                try:
                    state = await connect_probe(ip, port, self.tslow)
                    if state == "open":
                        if port not in self.opens_by_target[ti]:
                            self.opens_by_target[ti].add(port)
                            if not self.quiet:
                                print(f"{t}:{port} open")
                finally:
                    q.task_done()

        workers2 = [asyncio.create_task(worker2()) for _ in range(self.conc)]
        await q.join()

        for w in workers2:
            w.cancel()
        for w in workers2:
            with contextlib.suppress(asyncio.CancelledError):
                await w


def main():
    ap = argparse.ArgumentParser(description="Porter - fast TCP connect port scanner (Windows/macOS/Linux)")
    ap.add_argument("target", help="Host, CIDR, comma-list, IPv4 short ranges, or file with one target per line")
    ap.add_argument("-p", "--ports", default="1-1000",
                    help="Ports: e.g. 80,443 or 1-65535 or 'popular' (default: 1-1000)")
    ap.add_argument("-c", "--concurrency", type=int, default=300,
                    help="Max concurrent connects (default 300)")
    ap.add_argument("--tfast", type=float, default=0.30,
                    help="Fast timeout seconds (default 0.30)")
    ap.add_argument("--tslow", type=float, default=1.00,
                    help="Slow retry timeout seconds (default 1.00)")
    ap.add_argument("--no-retry", action="store_true",
                    help="Disable slow retry pass")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="Only print opens (suppress info lines)")
    args = ap.parse_args()

    # targets:
    # - if file: each line can itself be a single host/cidr/comma list/range
    # - else: args.target can be a single host/cidr/comma list/range
    targets: List[str] = []
    if os.path.isfile(args.target):
        with open(args.target, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.extend(parse_target_arg(line))
        targets = list(dict.fromkeys(targets))
    else:
        targets = parse_target_arg(args.target)

    ports = parse_ports(args.ports)
    if not ports:
        print("No ports to scan.", file=sys.stderr)
        sys.exit(2)

    if not args.quiet:
        print(
            f"[Porter] targets={len(targets)} ports={len(ports)} "
            f"concurrency={args.concurrency} timeouts=({args.tfast:.2f}s/{args.tslow:.2f}s) "
            f"retry={'on' if not args.no_retry else 'off'}"
        )

    scanner = Scanner(
        targets=targets,
        ports=ports,
        conc=args.concurrency,
        tfast=args.tfast,
        tslow=args.tslow,
        retry=(not args.no_retry),
        quiet=args.quiet
    )

    t0 = time.perf_counter()
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
    dt = time.perf_counter() - t0

    total_open = 0
    for i, t in enumerate(targets):
        opens = sorted(scanner.opens_by_target[i])
        if opens:
            print(f"{t}  open: {', '.join(map(str, opens))}")
            total_open += len(opens)

    if not args.quiet:
        dns_failed = len(scanner.dns_failed)
        if dns_failed:
            print(f"[info] DNS failed: {dns_failed} target(s) were not scanned.")
        print(f"[done] opens={total_open} in {dt:.2f}s")


if __name__ == "__main__":
    main()
