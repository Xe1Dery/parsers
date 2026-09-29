import argparse
import os
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
    try:
        root = ET.parse(filename).getroot()
    except ET.ParseError:
        continue
    if root.tag != "nmaprun":
        continue
    for host in root.findall(".//host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")

        for port in host.findall(".//port"):
            state_elem = port.find("state")
            if state_elem is None:
                continue
            state = state_elem.get("state", "")
            if state != "open" and not (args.include_filtered and state == "filtered"):
                continue
            portid = port.get("portid")
            if portid:
                ip_to_ports.setdefault(ip, []).append(portid)
                all_ports.add(portid)

for ip in ip_to_ports:
    ip_to_ports[ip] = list(set(ip_to_ports[ip]))

for ip, ports in ip_to_ports.items():
    if args.all_ports or args.output_mode:
        ports = all_ports
    if args.output_mode:
        with open("uniq_ip.txt", "a", encoding="utf-8") as f:
            f.write(f"{ip}\n")
        with open("uniq_ports.txt", "w", encoding="utf-8") as f:
            f.write(",".join(ports))
    if not args.output_mode:
        print(f"nmap {ip} -p {','.join(ports)} -oA nmap_{ip} {args.custom}")
