import argparse
import os
import sys
import xml.etree.ElementTree as ET

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

args = argparser.parse_args()

# Expand directories to XML files
expanded = []
for path in args.filenames:
    if os.path.isdir(path):
        for entry in sorted(os.listdir(path)):
            if entry.endswith(".xml"):
                expanded.append(os.path.join(path, entry))
    else:
        expanded.append(path)

ip_to_ports = {}
all_ports = set()

for filename in expanded:
    # iterparse: streaming, avoids building a full DOM tree
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
                            if state == "open" or (args.include_filtered and state == "filtered"):
                                portid = elem.get("portid")
                                if portid:
                                    ip_to_ports.setdefault(ip, []).append(portid)
                                    all_ports.add(portid)
                    elem.clear()
                elif tag == "host":
                    elem.clear()
    except (ET.ParseError, OSError):
        continue

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
