import argparse
import re

argparser = argparse.ArgumentParser(
    description="Парсинг вывода masscan в bash-скрипт nmap, вывод идёт в stdout. Вывод по умолчанию: nmap {IP} -p {ports} <ФЛАГИ -c> -oA nmap_{IP}",
    epilog="Пример использования: pyhton masscan-parser.py masscan_output_file > nmap.sh")
argparser.add_argument('filenames', type=str, nargs='+', help="Пути к файлу для парсинга")
argparser.add_argument('-c', '--custom', type=str, default='-Pn -sV --script default,vulscan/,vulners --script-args vulscandb=exploitdb.csv,mincvss=7.5 -T4', help="Включить режим задания своих флагов для nmap.")
argparser.add_argument('-c1', '--custom1', action='store_true', help="Включить режим задания своих флагов для nmap.")
argparser.add_argument('-a', '--all_ports', action='store_true', help="Добавить все уникальные порты ко всем командам nmap.")
argparser.add_argument('-om', '--output_mode', action='store_true', help="Вывести список IP и уникальных портов")

args = argparser.parse_args()

command = args.custom
if args.custom1:
    command = '-Pn -sV -O --script "default and not vulscan and not vulners"'

ip_to_ports = dict()
all_ports = set()

for filename in args.filenames:
    with open(filename, "r") as file:
        header = file.readline()
        pattern = ""

        if header.startswith("#masscan"):
            pattern = r"open tcp (\d+) ([.\d]+)"
        elif header.startswith("# Masscan"):
            pattern = r"Host: ([.\d]+).*Ports: (\d+)"
        elif header.startswith("["):
            pattern = r'"ip": "([.\d]+)".*"ports": \[ \{"port": (\d+)'
        elif header.startswith('<?xml'):
            pattern = r'addr="([.\d]+)".*portid="(\d+)"'

        iports = re.findall(pattern, file.read())

        for ip, port in iports:
            if "." in port:
                ip, port = port, ip

            if ip not in ip_to_ports.keys():
                ip_to_ports[ip] = []
            ip_to_ports[ip].append(port)
            all_ports.add(port)

for ip in ip_to_ports:
    ip_to_ports[ip] = list(set(ip_to_ports[ip]))  # Уникальные порты

for ip, ports in ip_to_ports.items():
    if args.all_ports or args.output_mode:
        ports = all_ports
    if args.output_mode:
        with open ("uniq_ip.txt", 'a', encoding='utf-8') as f:
            f.write(f"{ip}\n")
        with open ("uniq_ports.txt", 'w', encoding='utf-8') as f:
            f.write(f"{','.join(ports)}")
    if not args.output_mode:
        print(f"nmap {ip} -p {','.join(ports)} -oA nmap_{ip} {command}")