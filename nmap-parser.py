import argparse
import multiprocessing
import os
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor

argparser = argparse.ArgumentParser(
    description="Парсинг nmap XML в bash-скрипт nmap. Вывод: nmap {IP} -p {ports} <ФЛАГИ> -oA nmap_{IP}",
    epilog="Пример: python nmap-parser.py /tmp/kek/ > nmap.sh")
argparser.add_argument('filenames', type=str, nargs='+', help="Пути к XML-файлам или папкам с nmap XML")
argparser.add_argument('-c', '--custom', type=str,
    default='-Pn -sV --script default,vulscan/,vulners --script-args vulscandb=exploitdb.csv,mincvss=7.5 -T4',
    help="Флаги для nmap")
argparser.add_argument('-a', '--all_ports', action='store_true', help="Добавить все уникальные порты ко всем командам")
argparser.add_argument('-om', '--output_mode', action='store_true', help="Вывести список IP и уникальных портов в файлы")
argparser.add_argument('--include-filtered', action='store_true', help="Включить filtered порты")
argparser.add_argument('-w', '--workers', type=int, default=0,
    help="Кол-во процессов для параллельного разбора (0 = все ядра)")

args = argparser.parse_args()

# Expand directories to XML files (scandir is faster than listdir+isdir)
expanded = []
for path in args.filenames:
    if os.path.isdir(path):
        with os.scandir(path) as it:
            for entry in it:
                if entry.name.endswith(".xml") and entry.is_file(follow_symlinks=False):
                    expanded.append(entry.path)
    else:
        expanded.append(path)


def parse_file(filename):
    """Stream-parse one nmap XML. Returns list of (ip, portid) tuples."""
    results = []
    ip = None
    host_up = False
    try:
        for event, elem in ET.iterparse(filename, events=("start", "end")):
            tag = elem.tag
            if event == "start":
                if tag == "host":
                    ip = None
                    host_up = False
                elif tag == "status" and elem.get("state") == "up":
                    host_up = True
                elif tag == "address" and elem.get("addrtype") == "ipv4":
                    ip = elem.get("addr")
            elif event == "end":
                if tag == "port":
                    if host_up and ip is not None:
                        state_elem = elem.find("state")
                        if state_elem is not None:
                            state = state_elem.get("state", "")
                            if state == "open" or state == "filtered":
                                portid = elem.get("portid")
                                if portid:
                                    results.append((ip, portid, state))
                    elem.clear()
                elif tag == "host":
                    elem.clear()
    except (ET.ParseError, OSError):
        pass
    return results


def main():
    # Parallel parse across processes
    workers = args.workers or os.cpu_count() or 1
    ip_to_ports = {}
    all_ports = set()

    if workers > 1 and len(expanded) > 1:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            chunks = ex.map(parse_file, expanded, chunksize=256)
        for results in chunks:
            for ip, portid, state in results:
                if state == "open" or (args.include_filtered and state == "filtered"):
                    ip_to_ports.setdefault(ip, []).append(portid)
                    all_ports.add(portid)
    else:
        for filename in expanded:
            for ip, portid, state in parse_file(filename):
                if state == "open" or (args.include_filtered and state == "filtered"):
                    ip_to_ports.setdefault(ip, []).append(portid)
                    all_ports.add(portid)

    for ip in ip_to_ports:
        ip_to_ports[ip] = sorted(set(ip_to_ports[ip]), key=int)

    if args.output_mode:
        with open("uniq_ip.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(ip_to_ports) + "\n")
        with open("uniq_ports.txt", "w", encoding="utf-8") as f:
            f.write(",".join(sorted(all_ports, key=int)) + "\n")
    else:
        out = sys.stdout
        try:
            for ip, ports in ip_to_ports.items():
                if args.all_ports:
                    ports = sorted(all_ports, key=int)
                out.write(f"nmap {ip} -p {','.join(ports)} -oA nmap_{ip} {args.custom}\n")
        except BrokenPipeError:
            try:
                out.close()
            except BrokenPipeError:
                pass
            os._exit(0)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
