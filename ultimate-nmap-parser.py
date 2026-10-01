#!/usr/bin/env python3
"""
ultimate-nmap-parser.py — Python rewrite of ultimate-nmap-parser.sh
Parses Nmap grepable (.gnmap) output into various report formats.

Usage: python ultimate-nmap-parser.py [--all|--csv|--summary|...] file1.gnmap [file2.gnmap ...]
"""

import argparse
import csv
import multiprocessing
import os
import re
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

# --- Constants ---
VERSION = "1.0"
OUTDIR = "parse"
HOSTSDIR = "hosts"

OUTPUT_FILES = {
    "csv": "parsed_nmap.csv",
    "summary": "summary.txt",
    "closed": "closed-summary.txt",
    "ipport": "parsed_ipport.txt",
    "uphosts": "hosts_up.txt",
    "downhosts": "hosts_down.txt",
    "unique": "ports_unique.txt",
    "tcp": "ports_tcp.txt",
    "udp": "ports_udp.txt",
    "smb": "smb.txt",
    "web": "web-urls.txt",
    "ssl": "ssl.txt",
    "report1": "report1.txt",
    "portgroups": "port-groups.csv",
}

# Well-known port → service name mapping (for hostports naming)
KNOWN_SERVICES = {
    445: "smb", 161: "snmp", 25: "smtp", 21: "ftp", 2049: "nfs",
    22: "ssh", 23: "telnet", 111: "rpc", 137: "netbios", 139: "netbios",
    3389: "rdp", 53: "dns", 113: "ident", 79: "finger", 5432: "postgres",
    3306: "mysql", 1433: "mssql", 443: "https", 80: "http", 636: "ldap",
}

# Hostports entries to suppress (noisy/useless)
HOSTPORTS_SUPPRESS_SERVICES = {"msrpc", "unknown"}

# Precompiled regexes (hot path — parsed per line)
STATUS_RE = re.compile(r"Host:\s+([\d.]+)\s+\(.*?\)\s+Status:\s+(Up|Down)")
PORTS_RE = re.compile(r"Host:\s+([\d.]+)\s+\(.*?\)\s+Ports:\s+(.*)")
IGNORED_RE = re.compile(r"\s+Ignored\s+State:.*$")

# --- Data model ---
# Parsed port entry
# (host, port, status, protocol, service, version)


_IP_SORT_CACHE: dict = {}


def sort_ip(ip: str) -> tuple:
    """Sort key for IP addresses — numeric octet order.

    Memoized: at scale this key is requested millions of times, so caching the
    parsed octets turns repeated string splitting into a dict lookup.
    """
    cached = _IP_SORT_CACHE.get(ip)
    if cached is not None:
        return cached
    try:
        key = tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        key = (0, 0, 0, 0)
    _IP_SORT_CACHE[ip] = key
    return key


def parse_gnmap_file(filepath: str) -> tuple:
    """Parse a single .gnmap file.

    Returns (port_entries, host_status) where host_status maps IP->Up/Down.
    Each port_entries is a dict with host, status, port, port_status, protocol, service, version.
    """
    host_status = {}
    entries = []

    with open(filepath, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Status line: Host: IP (...) Status: Up/Down
            sm = STATUS_RE.match(line)
            if sm:
                ip, st = sm.group(1), sm.group(2)
                if ip not in host_status or st == "Up":
                    host_status[ip] = st
                continue

            # Ports line: Host: IP (...) Ports: ...
            pm = PORTS_RE.match(line)
            if not pm:
                continue
            ip = pm.group(1)
            ports_str = IGNORED_RE.sub("", pm.group(2))

            hst = host_status.get(ip, "Up")

            for entry in ports_str.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("/")
                if len(parts) < 3:
                    continue
                port = parts[0]
                port_status = parts[1]
                protocol = parts[2]
                # gnmap port format: port/state/proto/owner/service/rpc_info/version/
                service = parts[4] if len(parts) > 4 else ""
                version = parts[6] if len(parts) > 6 else ""

                entries.append({
                    "host": ip, "status": hst, "port": port,
                    "port_status": port_status, "protocol": protocol,
                    "service": service, "version": version
                })

    return entries, host_status


# Entry field order used for the compact tuple form that crosses IPC.
ENTRY_FIELDS = ("host", "status", "port", "port_status", "protocol", "service", "version")


def _entry_key(t: tuple) -> tuple:
    """Dedup key for a compact entry tuple: (host, port, protocol, port_status)."""
    return (t[0], t[2], t[4], t[3])


def _parse_worker(filepath: str) -> tuple:
    """ProcessPool worker: parse one file, dedup it, return compact tuples.

    Returning tuples instead of dicts keeps the pickled payload small, which
    matters when a scan set contains millions of port entries.
    """
    entries, hstatus = parse_gnmap_file(filepath)
    seen = set()
    out = []
    for e in entries:
        t = (e["host"], e["status"], e["port"], e["port_status"],
             e["protocol"], e["service"], e["version"])
        k = _entry_key(t)
        if k in seen:
            continue
        seen.add(k)
        out.append(t)
    return out, hstatus


def collect_parsed(filepaths: list, workers: int = 0) -> tuple:
    """Parse all files, returning (sorted_entries, merged_host_status).

    Deduplicates on (host, port, protocol, port_status) — every report already
    drops these duplicates internally, so this shrinks the working set without
    changing any output. Files are parsed in a process pool when workers > 1.
    """
    merged_status: dict = {}
    unique: list = []
    seen: set = set()

    def merge(entries, hstatus):
        for t in entries:
            k = _entry_key(t)
            if k in seen:
                continue
            seen.add(k)
            unique.append(dict(zip(ENTRY_FIELDS, t)))
        for ip, st in hstatus.items():
            if ip not in merged_status or st == "Up":
                merged_status[ip] = st

    n = len(filepaths)
    if workers <= 0:
        workers = os.cpu_count() or 1

    if workers > 1 and n >= 64:
        chunksize = max(1, min(256, n // (workers * 4)))
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for entries, hstatus in ex.map(_parse_worker, filepaths, chunksize=chunksize):
                merge(entries, hstatus)
    else:
        for fp in filepaths:
            merge(*_parse_worker(fp))

    unique.sort(key=lambda e: sort_ip(e["host"]))
    return unique, merged_status


def get_open_entries(all_entries: list) -> list:
    return [e for e in all_entries if e["port_status"] == "open"]


def get_closed_entries(all_entries: list) -> list:
    return [e for e in all_entries if e["port_status"] == "closed"]


# --- Output generators ---

def generate_csv(all_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["csv"])
    # Include both open and closed (bash version includes both)
    entries = [e for e in all_entries if e["port_status"] in ("open", "closed")]
    if not entries:
        return None
    seen = set()
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["HOST", "PORT", "STATUS", "PROTOCOL", "SERVICE", "VERSION"])
        for e in sorted(entries, key=lambda x: (sort_ip(x["host"]), int(x["port"]))):
            key = (e["host"], e["port"], e["protocol"])
            if key in seen:
                continue
            seen.add(key)
            writer.writerow([e["host"], e["port"], e["port_status"], e["protocol"],
                             e["service"], e["version"]])
    return path


def generate_summary(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["summary"])
    if not open_entries:
        return None

    # Deduplicate by (host, port, protocol)
    seen = set()
    unique_entries = []
    for e in sorted(open_entries, key=lambda x: (sort_ip(x["host"]), int(x["port"]))):
        key = (e["host"], e["port"], e["protocol"])
        if key not in seen:
            seen.add(key)
            unique_entries.append(e)

    # Calculate column widths from data
    host_w = max((len(e["host"]) for e in unique_entries), default=4)
    port_w = max((len(e["port"]) for e in unique_entries), default=4)
    proto_w = max((len(e["protocol"]) for e in unique_entries), default=3)
    svc_w = max((len(e["service"]) for e in unique_entries), default=7)
    ver_w = max((len(e["version"]) for e in unique_entries), default=7)

    # Build format: | HOST | PORT / PROTO | SERVICE - VERSION |
    # Right side: SERVICE + " - " + VERSION (or just SERVICE if no version)
    right_w = svc_w + ver_w + 3  # " - " between service and version
    total_w = host_w + port_w + proto_w + right_w + 13  # 13 = spaces, pipes, slashes

    border = "+" + "=" * (total_w - 2) + "+"

    with open(path, "w") as f:
        last_host = None
        for e in unique_entries:
            if e["host"] != last_host:
                f.write(border + "\n")
            pp = f"{e['port']} / {e['protocol']}"
            if e["version"]:
                sv = f"{e['service']} - {e['version']}"
            else:
                sv = e["service"]
            f.write(f"| {e['host']:<{host_w}} | {pp:<{port_w + proto_w + 3}} | {sv:<{right_w}} |\n")
            last_host = e["host"]
        f.write(border + "\n")
    return path


def generate_ipport(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["ipport"])
    if not open_entries:
        return None
    seen = set()
    lines = []
    for e in sorted(open_entries, key=lambda x: (sort_ip(x["host"]), int(x["port"]))):
        key = (e["host"], e["port"])
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{e['host']}:{e['port']}")
    if lines:
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path
    return None


def generate_uphosts(open_entries: list, host_status: dict, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["uphosts"])
    # Hosts that are "Up" OR have any open port
    up_hosts = set()
    for e in open_entries:
        up_hosts.add(e["host"])
    for host, st in host_status.items():
        if st == "Up":
            up_hosts.add(host)
    if not up_hosts:
        return None
    with open(path, "w") as f:
        for ip in sorted(up_hosts, key=sort_ip):
            f.write(ip + "\n")
    return path


def generate_downhosts(host_status: dict, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["downhosts"])
    down = sorted([h for h, s in host_status.items() if s == "Down"], key=sort_ip)
    if not down:
        return None
    with open(path, "w") as f:
        for ip in down:
            f.write(ip + "\n")
    return path


def generate_unique_ports(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["unique"])
    ports = sorted(set(int(e["port"]) for e in open_entries if e["port"].isdigit()))
    if not ports:
        return None
    with open(path, "w") as f:
        f.write(",".join(str(p) for p in ports) + "\n")
    return path


def generate_tcp_ports(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["tcp"])
    ports = sorted(set(
        int(e["port"]) for e in open_entries
        if e["protocol"] == "tcp" and e["port"].isdigit()
    ))
    if not ports:
        return None
    with open(path, "w") as f:
        f.write(",".join(str(p) for p in ports) + "\n")
    return path


def generate_udp_ports(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["udp"])
    ports = sorted(set(
        int(e["port"]) for e in open_entries
        if e["protocol"] == "udp" and e["port"].isdigit()
    ))
    if not ports:
        return None
    with open(path, "w") as f:
        f.write(",".join(str(p) for p in ports) + "\n")
    return path


def generate_smb(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["smb"])
    smb_hosts = sorted(set(
        e["host"] for e in open_entries
        if e["port"] == "445" and e["protocol"] == "tcp"
    ), key=sort_ip)
    if not smb_hosts:
        return None
    with open(path, "w") as f:
        for ip in smb_hosts:
            f.write(f"smb://{ip}\n")
    return path


def generate_web(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["web"])
    urls = set()
    for e in open_entries:
        port = e["port"]
        svc = e["service"].lower() if e["service"] else ""
        ver = e["version"].lower() if e["version"] else ""
        # Well-known web ports
        if port == "80":
            urls.add(f"http://{e['host']}:{port}/")
        if port == "443":
            urls.add(f"https://{e['host']}:{port}/")
        if port == "8080":
            urls.add(f"http://{e['host']}:{port}/")
        if port == "8443":
            urls.add(f"https://{e['host']}:{port}/")
        # Service-based detection
        if svc == "http":
            urls.add(f"http://{e['host']}:{port}/")
        if "ssl" in svc:
            urls.add(f"https://{e['host']}:{port}/")
        if "web" in ver:
            urls.add(f"http://{e['host']}:{port}/")
    if not urls:
        return None
    with open(path, "w") as f:
        for url in sorted(urls, key=lambda u: (sort_ip(u.split("://")[1].split(":")[0]),
                                                  int(u.split(":")[-1].rstrip("/")))):
            f.write(url + "\n")
    return path


def generate_ssl(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["ssl"])
    ssl_entries = set()
    for e in open_entries:
        port = e["port"]
        svc = e["service"].lower() if e["service"] else ""
        ver = e["version"].lower() if e["version"] else ""
        if port == "443":
            ssl_entries.add(f"{e['host']}:{port}")
        if "ssl" in svc or "ssl" in ver or "tls" in svc or "tls" in ver:
            ssl_entries.add(f"{e['host']}:{port}")
    if not ssl_entries:
        return None
    with open(path, "w") as f:
        for entry in sorted(ssl_entries, key=lambda x: (sort_ip(x.split(":")[0]),
                                                           int(x.split(":")[1]))):
            f.write(entry + "\n")
    return path


def generate_hostports(open_entries: list, outdir: str):
    hostsdir = os.path.join(outdir, HOSTSDIR)
    # Clean and recreate
    if os.path.exists(hostsdir):
        import shutil
        shutil.rmtree(hostsdir)
    os.makedirs(hostsdir)

    # Group by (protocol, port, service)
    groups: dict[tuple, list[str]] = defaultdict(list)
    for e in open_entries:
        port = e["port"]
        proto = e["protocol"]
        svc_raw = e["service"] if e["service"] else ""

        # Apply service name overrides and suppressions
        port_int = int(port) if port.isdigit() else 0
        if port_int in KNOWN_SERVICES:
            svc = KNOWN_SERVICES[port_int]
        elif proto == "udp" and port_int == 177:
            svc = "xdmcp"
        elif proto == "udp" and svc_raw.lower() == "unknown":
            continue  # suppress noisy UDP unknown
        elif svc_raw.lower() in HOSTPORTS_SUPPRESS_SERVICES:
            continue  # suppress msrpc spam
        elif not svc_raw or svc_raw == "-":
            continue  # suppress entries without service info
        else:
            svc = svc_raw.replace("-", "").replace("?", "").replace("|", "")

        groups[(proto, port_int, svc)].append(e["host"])

    for (proto, port, svc), hosts in sorted(groups.items()):
        fname = f"{proto}_{port}-{svc}.txt"
        with open(os.path.join(hostsdir, fname), "w") as f:
            for ip in sorted(set(hosts), key=sort_ip):
                f.write(ip + "\n")

    return hostsdir


def generate_closed_summary(closed_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["closed"])
    if not closed_entries:
        return None

    # Group by host
    host_ports: dict[str, set] = defaultdict(set)
    for e in closed_entries:
        if e["port"].isdigit():
            host_ports[e["host"]].add(int(e["port"]))

    if not host_ports:
        return None

    with open(path, "w") as f:
        for host in sorted(host_ports, key=sort_ip):
            ports = sorted(host_ports[host])
            ports_str = ", ".join(str(p) for p in ports)
            f.write(f"Closed Ports For Host: {host}\n")
            f.write(f"\t{ports_str}\n\n")
    return path


def generate_report1(open_entries: list, outdir: str):
    path = os.path.join(outdir, OUTPUT_FILES["report1"])
    host_ports: dict[str, set] = defaultdict(set)
    for e in open_entries:
        if e["port"].isdigit():
            host_ports[e["host"]].add(int(e["port"]))

    if not host_ports:
        return None

    with open(path, "w") as f:
        for host in sorted(host_ports, key=sort_ip):
            ports = sorted(host_ports[host])
            if not ports:
                continue
            ports_str = ", ".join(str(p) for p in ports)
            f.write(f"{host} [{ports_str}]\n")
    return path


def generate_portgroups(open_entries: list, outdir: str):
    """Write hosts grouped by identical open-port set, one row per group.

    CSV columns: ports (port/proto pairs joined by ";"), count, hosts
    (IPs joined by ";"). Groups are sorted by their port set.
    """
    path = os.path.join(outdir, OUTPUT_FILES["portgroups"])
    host_ports: dict[str, set] = defaultdict(set)
    for e in open_entries:
        if e["port"].isdigit():
            host_ports[e["host"]].add((int(e["port"]), e["protocol"]))

    if not host_ports:
        return None

    groups: dict[tuple, list[str]] = defaultdict(list)
    for host, ports in host_ports.items():
        groups[tuple(sorted(ports))].append(host)

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ports", "count", "hosts"])
        for ports, hosts in sorted(groups.items()):
            hosts = sorted(set(hosts), key=sort_ip)
            ports_str = ";".join(f"{p}/{proto}" for p, proto in ports)
            writer.writerow([ports_str, len(hosts), ";".join(hosts)])
    return path


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="Parse Nmap grepable (.gnmap) files into various report formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s *.gnmap --all
  %(prog)s scan.gnmap --csv --unique -o results/
  %(prog)s scan.gnmap --web --ssl
        """
    )
    parser.add_argument("files", nargs="+", help="One or more .gnmap files or directories to scan")
    parser.add_argument("--all", action="store_true", help="Generate ALL reports (except --report1)")
    parser.add_argument("--csv", action="store_true", help=f"Create CSV file ({OUTPUT_FILES['csv']})")
    parser.add_argument("--summary", action="store_true", help=f"Host summary report ({OUTPUT_FILES['summary']})")
    parser.add_argument("--closed", action="store_true", help=f"Closed ports summary ({OUTPUT_FILES['closed']})")
    parser.add_argument("--unique", action="store_true", help=f"Unique open ports ({OUTPUT_FILES['unique']})")
    parser.add_argument("--tcp", action="store_true", help=f"Open TCP ports ({OUTPUT_FILES['tcp']})")
    parser.add_argument("--udp", action="store_true", help=f"Open UDP ports ({OUTPUT_FILES['udp']})")
    parser.add_argument("--up", action="store_true", help=f"Up hosts ({OUTPUT_FILES['uphosts']})")
    parser.add_argument("--down", action="store_true", help=f"Down hosts ({OUTPUT_FILES['downhosts']})")
    parser.add_argument("--ipport", action="store_true", help=f"IP:PORT listing ({OUTPUT_FILES['ipport']})")
    parser.add_argument("--smb", action="store_true", help=f"SMB paths ({OUTPUT_FILES['smb']})")
    parser.add_argument("--web", action="store_true", help=f"Web URLs ({OUTPUT_FILES['web']})")
    parser.add_argument("--ssl", action="store_true", help=f"SSL/TLS hosts ({OUTPUT_FILES['ssl']})")
    parser.add_argument("--hostports", action="store_true", help=f"Per-protocol host files ({HOSTSDIR}/)")
    parser.add_argument("--report1", action="store_true", help=f"IP[port1,port2] report ({OUTPUT_FILES['report1']})")
    parser.add_argument("--portgroups", action="store_true",
                        help=f"Hosts grouped by identical open ports, one row per group ({OUTPUT_FILES['portgroups']})")
    parser.add_argument("-o", "--outdir", default=None,
                        help=f"Output directory (default: {OUTDIR} with --all, else .)")
    parser.add_argument("-w", "--workers", type=int, default=0,
                        help="Processes for parallel parsing (0 = all cores, 1 = single)")

    args = parser.parse_args()

    if args.all:
        args.csv = args.summary = args.unique = args.tcp = args.udp = True
        args.up = args.down = args.ipport = args.smb = args.ssl = args.web = True
        args.hostports = args.closed = args.portgroups = True
        args.report1 = False

    if not any([args.csv, args.summary, args.unique, args.tcp, args.udp,
                args.up, args.down, args.ipport, args.smb, args.ssl,
                args.web, args.hostports, args.closed, args.report1,
                args.portgroups]):
        parser.print_help()
        sys.exit(1)

    outdir = args.outdir or (OUTDIR if args.all else os.getcwd())
    os.makedirs(outdir, exist_ok=True)

    # Expand directories to .gnmap files (scandir avoids shell glob/ARG_MAX limits)
    inputs = []
    for path in args.files:
        if os.path.isdir(path):
            with os.scandir(path) as it:
                for entry in it:
                    if entry.name.endswith(".gnmap") and entry.is_file(follow_symlinks=False):
                        inputs.append(entry.path)
        else:
            inputs.append(path)

    # Collect all data in one pass
    all_entries, host_status = collect_parsed(inputs, args.workers)

    if not all_entries:
        print("[!] No data found in input files", file=sys.stderr)
        sys.exit(1)

    # Slice the working set once instead of rescanning it in every generator
    open_entries = get_open_entries(all_entries)
    closed_entries = get_closed_entries(all_entries)

    # Generate requested outputs
    generated = []
    if args.csv:
        p = generate_csv(all_entries, outdir); generated.append(p)
    if args.summary:
        p = generate_summary(open_entries, outdir); generated.append(p)
    if args.ipport:
        p = generate_ipport(open_entries, outdir); generated.append(p)
    if args.unique:
        p = generate_unique_ports(open_entries, outdir); generated.append(p)
    if args.tcp:
        p = generate_tcp_ports(open_entries, outdir); generated.append(p)
    if args.udp:
        p = generate_udp_ports(open_entries, outdir); generated.append(p)
    if args.up:
        p = generate_uphosts(open_entries, host_status, outdir); generated.append(p)
    if args.down:
        p = generate_downhosts(host_status, outdir); generated.append(p)
    if args.smb:
        p = generate_smb(open_entries, outdir); generated.append(p)
    if args.web:
        p = generate_web(open_entries, outdir); generated.append(p)
    if args.ssl:
        p = generate_ssl(open_entries, outdir); generated.append(p)
    if args.hostports:
        p = generate_hostports(open_entries, outdir); generated.append(p)
    if args.closed:
        p = generate_closed_summary(closed_entries, outdir); generated.append(p)
    if args.report1:
        p = generate_report1(open_entries, outdir); generated.append(p)
    if args.portgroups:
        p = generate_portgroups(open_entries, outdir); generated.append(p)

    # Single line of output: where things were saved
    count = len([p for p in generated if p])
    print(f"[+] {count} file(s) written to: {os.path.abspath(outdir)}")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
