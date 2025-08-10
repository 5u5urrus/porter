#!/usr/bin/env python3
"""
Porter — focused, fast TCP connect port scanner (Windows/macOS/Linux)
- Popular-first ordering so opens show up early (port-major wavefront across hosts)
- Streams open ports immediately (no waiting for completion)
- Two-pass timeouts: fast pass, then retry only timeouts with a longer timeout
- Tiny backoff on local resource exhaustion (EMFILE/WSAENOBUFS/EADDRINUSE)
- No raw sockets, no banners, no fluff — just fast and accurate simple and configurable TCP scanning

Author: Vahe Demirkhanyan
"""

import asyncio
import sys
import ipaddress
import argparse
import socket
import time
import os
import contextlib
import errno
from typing import List, Set, Tuple, Dict

# the popular ports to scan first
POPULAR_PORTS = [
    80, 443, 22, 3389, 445, 1433, 3306, 53, 25, 110, 143, 995, 993, 587, 465,
    21, 23, 8080, 8443, 6379, 27017, 9200, 5000, 8000, 8888, 5900, 5901, 389,
    636, 1521, 2049, 111, 139, 135, 7001, 8081, 8082, 15672, 5672, 11211, 514,
    853, 8530, 4369, 5432, 27018, 27019, 25565
]

def expand_targets(arg: str) -> List[str]:
    """Return a list of IPs/hosts from single host or CIDR."""
    try:
        net = ipaddress.ip_network(arg, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [arg.strip()]

def parse_ports(spec: str) -> List[int]:
    """Parse 'popular' or comma/range list like '80,443,8000-8100'."""
    if spec == "popular":
        # dedupe and keep order
        return list(dict.fromkeys(POPULAR_PORTS))
    ports: Set[int] = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            a, b = int(a), int(b)
            if a > b: 
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def order_ports(ports: List[int]) -> List[int]:
    """Popular-first ordering, then remaining ascending."""
    rank = {p: i for i, p in enumerate(POPULAR_PORTS)}
    return sorted(ports, key=lambda p: (0, rank[p]) if p in rank else (1, p))

async def probe_tcp(host: str, port: int, timeout: float) -> Tuple[str, float]:
    """
    Try TCP connect; classify result as:
      - 'open'      : TCP handshake succeeded
      - 'closed'    : immediate refusal
      - 'filtered'  : timeout/unreachable
      - 'backoff'   : local resource pressure (EMFILE / WSAENOBUFS / EADDRINUSE)
    Returns (state, seconds_elapsed).
    """
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        dt = time.perf_counter() - t0
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return "open", dt
    except asyncio.TimeoutError:
        return "filtered", time.perf_counter() - t0
    except ConnectionRefusedError:
        return "closed", time.perf_counter() - t0
    except OSError as e:
        code = getattr(e, "errno", None)
        # POSIX + Windows: map errors
        closed_codes = {errno.ECONNREFUSED, 10061}
        filtered_codes = {
            errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH, 10060, 10051, 10065
        }
        resource_codes = {getattr(errno, "EMFILE", 24), getattr(errno, "EADDRINUSE", 98), 10055, 10048}
        if code in resource_codes:
            return "backoff", time.perf_counter() - t0
        if code in closed_codes:
            state = "closed"
        elif code in filtered_codes:
            state = "filtered"
        else:
            state = "filtered"
        return state, time.perf_counter() - t0

class Scanner:
    def __init__(self, hosts: List[str], ports: List[int],
                 max_conc: int = 300, t_fast: float = 0.30, t_slow: float = 1.00,
                 retry: bool = True, quiet: bool = False):
        self.hosts = hosts
        self.ports = order_ports(ports)
        self.max_conc = max_conc
        self.t_fast = t_fast
        self.t_slow = t_slow
        self.retry = retry
        self.quiet = quiet
        self.results: Dict[str, Dict[int, str]] = {h: {} for h in hosts}

    async def run(self):
        # --- pass 1 --- fast timeout (port-major wavefront across all hosts) ----
        work = asyncio.Queue()
        for port in self.ports:
            for host in self.hosts:
                work.put_nowait((host, port, self.t_fast))

        async def worker(queue: asyncio.Queue):
            while True:
                try:
                    host, port, to = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                state, dt = await probe_tcp(host, port, to)
                if state == "backoff":
                    # brief backoff, then requeue the same item to try again later
                    await asyncio.sleep(0.3)
                    queue.put_nowait((host, port, to))
                    queue.task_done()
                    continue
                self.results[host][port] = state
                if state == "open" and not self.quiet:
                    print(f"{host}:{port} open  ({int(dt*1000)} ms)")
                queue.task_done()

        workers = [asyncio.create_task(worker(work)) for _ in range(self.max_conc)]
        await asyncio.gather(*workers)

        if not self.retry:
            return

        # pass 2: retry only filtered with longer timeout (popular-first again) ----
        # Build mapping of port -> [hosts] for filtered results
        filtered_by_port: Dict[int, List[str]] = {}
        for host in self.hosts:
            for port, state in self.results[host].items():
                if state == "filtered":
                    filtered_by_port.setdefault(port, []).append(host)

        if not filtered_by_port:
            return

        work2 = asyncio.Queue()
        for port in order_ports(list(filtered_by_port.keys())):
            for host in filtered_by_port[port]:
                work2.put_nowait((host, port, self.t_slow))

        if work2.qsize() and not self.quiet:
            print(f"[info] Retrying {work2.qsize()} filtered ports with longer timeout...")

        workers2 = [asyncio.create_task(worker(work2)) for _ in range(self.max_conc)]
        await asyncio.gather(*workers2)

def main():
    ap = argparse.ArgumentParser(
        description="PortX — fast and accurate TCP port scanner (Windows/macOS/Linux)"
    )
    ap.add_argument("target", help="Host, CIDR, or file with one target per line")
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

    # building the list (allow file with mixed hosts/CIDRs, dedupe)
    if os.path.isfile(args.target):
        hosts: List[str] = []
        with open(args.target, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                hosts.extend(expand_targets(line))
        #preserving order
        hosts = list(dict.fromkeys(hosts))
    else:
        hosts = list(dict.fromkeys(expand_targets(args.target)))

    ports = parse_ports(args.ports)
    if not ports:
        print("No ports to scan.", file=sys.stderr)
        sys.exit(2)

    if not args.quiet:
        print(f"[PortX] targets={len(hosts)} ports={len(ports)} "
              f"concurrency={args.concurrency} timeouts=({args.tfast:.2f}s/{args.tslow:.2f}s) "
              f"retry={'on' if not args.no_retry else 'off'}")

    scanner = Scanner(
        hosts=hosts,
        ports=ports,
        max_conc=args.concurrency,
        t_fast=args.tfast,
        t_slow=args.tslow,
        retry=(not args.no_retry),
        quiet=args.quiet
    )

    t0 = time.perf_counter()
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Aborted.")

    total_open = 0
    for h in hosts:
        opens = [p for p, s in scanner.results[h].items() if s == "open"]
        if opens:
            print(f"{h}  open: {', '.join(str(p) for p in sorted(opens))}")
            total_open += len(opens)

    if not args.quiet:
        dt = time.perf_counter() - t0
        total = len(hosts) * len(ports)
        rate = int(total / dt) if dt > 0 else 0
        print(f"[done] scanned={total} in {dt:.2f}s  ~{rate} ports/s   opens={total_open}")

if __name__ == "__main__":
    main()
