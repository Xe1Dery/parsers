import argparse
import re
import xml.etree.ElementTree as ET

argparser = argparse.ArgumentParser(
    description="Парсинг вывода nmap (XML/gnmap/nmap) в bash-скрипт nmap. Вывод: nmap {IP} -p {ports} <ФЛАГИ> -oA nmap_{IP}",
    epilog="Пример: python nmap-parser.py /tmp/kek/*.xml > nmap.sh")
argparser.add_argument('filenames', type=str, nargs='+', help="Пути к файлам nmap (xml, gnmap, nmap)")
argparser.add_argument('-c', '--custom', type=str,
    default='-Pn -sV --script default,vulscan/,vulners --script-args vulscandb=exploitdb.csv,mincvss=7.5 -T4',
    help="Флаги для nmap")
argparser.add_argument('-a', '--all_ports', action='store_true', help="Добавить все уникальные порты ко всем командам")
argparser.add_argument('-om', '--output_mode', action='store_true', help="Вывести список IP и уникальных портов в файлы")
argparser.add_argument('--open-only', action='store_true', default=True, help="Только открытые порты (по умолчанию)")
argparser.add_argument('--include-filtered', action='store_true', help="Включить filtered порты")

args = argparser.parse_args()

ip_to_ports = {}
all_ports = set()

for filename in args.filenames:
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Detect format
    if content.lstrip().startswith("<?xml"):
        # XML format
        root = ET.fromstring(content)
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

    elif "#nmap" in content[:200].lower() or "Host:" in content[:200]:
        # gnmap format: Host: IP ()  Status: Up\nHost: IP () Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
        for line in content.splitlines():
            if not line.startswith("Host:"):
                continue
            m = re.match(r"Host:\s+([.\d]+)", line)
            if not m:
                continue
            ip = m.group(1)
            ports_match = re.search(r"Ports:\s+(.*)", line)
            if not ports_match:
                continue
            for port_entry in ports_match.group(1).split(","):
                port_entry = port_entry.strip()
                # format: 22/open/tcp//ssh///
                parts = port_entry.split("/")
                if len(parts) >= 2:
                    portid = parts[0]
                    state = parts[1]
                    if state == "open" or (args.include_filtered and state == "filtered"):
                        ip_to_ports.setdefault(ip, []).append(portid)
                        all_ports.add(portid)

    else:
        # nmap normal format: parse "PORT STATE SERVICE" table under each Nmap scan report
        current_ip = None
        for line in content.splitlines():
            m = re.match(r"Nmap scan report for ([.\d]+)", line)
            if m:
                current_ip = m.group(1)
                continue
            if current_ip:
                # e.g. "22/tcp   open  ssh"
                m = re.match(r"(\d+)/(?:tcp|udp)\s+(open|filtered)", line.strip())
                if m:
                    portid, state = m.group(1), m.group(2)
                    if state == "open" or (args.include_filtered and state == "filtered"):
                        ip_to_ports.setdefault(current_ip, []).append(portid)
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
