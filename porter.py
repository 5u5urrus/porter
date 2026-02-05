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

TOP1000_SPEC = (
    "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,"
    "106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,"
    "254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,"
    "458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,"
    "625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,"
    "783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,"
    "999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,"
    "1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,"
    "1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,"
    "1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,"
    "1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,"
    "1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,"
    "1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,"
    "1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,"
    "2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,"
    "2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,"
    "2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,"
    "2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,"
    "3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,"
    "3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,"
    "3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,"
    "3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,"
    "3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,"
    "4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,"
    "5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,"
    "5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,"
    "5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,"
    "5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,"
    "6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,"
    "6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,"
    "7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,"
    "7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,"
    "8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,"
    "8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,"
    "9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,"
    "9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,"
    "9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,"
    "10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,"
    "12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,"
    "16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,"
    "19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,"
    "22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,"
    "30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,"
    "40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,"
    "49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,"
    "52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,"
    "60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389,280,4567,7001,8008,9080"
)


def expand_targets(arg: str) -> List[str]:
    try:
        net = ipaddress.ip_network(arg, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [arg.strip()]


def _expand_ipv4_last_octet_range(token: str) -> List[str]:
    s = token.strip()
    if not s:
        return []
    if s.count(".") != 3 or "-" not in s:
        return [s]
    left, right = s.rsplit(".", 1)
    if "-" not in right:
        return [s]
    a_str, b_str = right.split("-", 1)
    if not (a_str.isdigit() and b_str.isdigit()):
        return [s]
    try:
        ipaddress.IPv4Address(f"{left}.0")
    except Exception:
        return [s]
    a = int(a_str)
    b = int(b_str)
    if not (0 <= a <= 255 and 0 <= b <= 255):
        return [s]
    if a > b:
        a, b = b, a
    parts = left.split(".")
    if len(parts) != 3 or any((not p.isdigit()) or not (0 <= int(p) <= 255) for p in parts):
        return [s]
    return [f"{left}.{i}" for i in range(a, b + 1)]


def parse_target_arg(arg: str) -> List[str]:
    out: List[str] = []
    for raw in arg.split(","):
        tok = raw.strip()
        if not tok:
            continue
        if "/" in tok:
            out.extend(expand_targets(tok))
            continue
        out.extend(_expand_ipv4_last_octet_range(tok))
    return list(dict.fromkeys(out))


def parse_ports(spec: str) -> List[int]:
    if spec == "popular":
        return list(dict.fromkeys(POPULAR_PORTS))
    if spec in {"top", "top1000", "nmap"}:
        spec = TOP1000_SPEC

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
            ips = list(dict.fromkeys(v4 + v6))
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
    ap = argparse.ArgumentParser(description="Porter — fast TCP connect port scanner (Windows/macOS/Linux)")
    ap.add_argument("target", help="Host, CIDR, comma-list, IPv4 short ranges, or file with one target per line")

    # DEFAULT CHANGE: now top 1000 common ports (Nmap-style) instead of 1-1000
    ap.add_argument(
        "-p", "--ports",
        default="top",
        help="Ports: e.g. 80,443 or 1-65535 or 'popular' or 'top' (default: top 1000)"
    )

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
