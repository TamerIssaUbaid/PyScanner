#!/usr/bin/env python3
"""
PyScanner - Port Scanner
"""

import socket
import argparse
import sys
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── SERVIÇOS CONHECIDOS ───────────────────────────────────────────
SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-Sub", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    27017: "MongoDB",
}

# ─── ANÁLISE DE RISCO ──────────────────────────────────────────────
RISKS = {
    21:  ("ALTA",    "FTP transmite credenciais em texto claro"),
    22:  ("MEDIA",   "SSH seguro, mas vulneravel a brute-force"),
    23:  ("CRITICA", "Telnet transmite tudo em texto claro!"),
    25:  ("ALTA",    "SMTP aberto pode ser usado para relay de spam"),
    53:  ("MEDIA",   "DNS exposto pode ser alvo de amplificacao DDoS"),
    135: ("ALTA",    "MS-RPC: vetor comum de ataques Windows"),
    139: ("ALTA",    "NetBIOS legado, vulneravel a exploits Windows"),
    445: ("CRITICA", "SMB: vetor WannaCry/EternalBlue. Bloquear!"),
    1433:("ALTA",    "MSSQL exposto e risco critico de SQL injection"),
    3306:("ALTA",    "MySQL exposto na internet e risco critico"),
    3389:("ALTA",    "RDP: principal vetor de ransomware"),
    4444:("CRITICA", "Porta padrao Metasploit — possivel backdoor!"),
    5900:("ALTA",    "VNC sem criptografia expoe desktop remoto"),
    6379:("CRITICA", "Redis sem auth permite execucao remota de cmds"),
    27017:("ALTA",   "MongoDB pode estar sem autenticacao"),
}

# ─── CORES ANSI ────────────────────────────────────────────────────
R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

TOP_PORTS = sorted({
    21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,
    465,587,636,993,995,1080,1433,1521,1723,2049,3306,3389,
    4444,5432,5900,6379,8080,8443,8888,9200,27017,
} | set(range(1, 1025)))


# ─── FUNÇÕES ───────────────────────────────────────────────────────

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = target
        return ip, hostname
    except socket.gaierror as e:
        print(f"{RED}[ERRO] Nao foi possivel resolver '{target}': {e}{R}")
        sys.exit(1)


def grab_banner(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    return banner[:120]
            except Exception:
                pass
            if port in (80, 8080, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                return s.recv(512).decode("utf-8", errors="ignore").strip()[:120]
    except Exception:
        return None


def scan_port_tcp(ip, port, timeout, grab):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = SERVICES.get(port, "unknown")
            banner = grab_banner(ip, port) if grab and port in {21,22,25,80,8080,110,143} else None
            return {"port": port, "state": "open", "proto": "tcp", "service": service, "banner": banner}
    except Exception:
        return None


def scan_port_udp(ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00" * 8, (ip, port))
        s.recvfrom(1024)
        s.close()
        return {"port": port, "state": "open", "proto": "udp", "service": SERVICES.get(port,"unknown"), "banner": None}
    except socket.timeout:
        s.close()
        return {"port": port, "state": "open|filtered", "proto": "udp", "service": SERVICES.get(port,"unknown"), "banner": None}
    except Exception:
        try: s.close()
        except: pass
        return None


def guess_os(ip):
    import subprocess
    try:
        r = subprocess.run(["ping","-c","1","-W","1",ip], capture_output=True, text=True, timeout=3)
        for token in r.stdout.lower().split():
            if "ttl=" in token:
                ttl = int(token.split("=")[1])
                if ttl <= 64:   return f"Linux/Unix (TTL={ttl})"
                if ttl <= 128:  return f"Windows (TTL={ttl})"
                return f"Cisco/Roteador (TTL={ttl})"
    except Exception:
        pass
    return "Indeterminado"


def parse_ports(s):
    ports = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)


def print_risk(port):
    if port in RISKS:
        nivel, msg = RISKS[port]
        cor = RED if nivel == "CRITICA" else (YELLOW if nivel == "ALTA" else CYAN)
        print(f"          {cor}[{nivel}]{R} {DIM}{msg}{R}")


def run_scan(target, ports, udp=False, threads=100, timeout=1.0, grab=True, output=None, verbose=False):
    ip, hostname = resolve_host(target)
    start = datetime.now()

    print()
    print(f"{CYAN}{BOLD}{'═'*62}{R}")
    print(f"{CYAN}{BOLD}  PyScanner — Port Scanner | Segurança da Informação{R}")
    print(f"{CYAN}{BOLD}{'═'*62}{R}")
    print(f"  {BOLD}Alvo      :{R} {YELLOW}{target}{R}" + (f"  ({hostname})" if hostname != target else ""))
    print(f"  {BOLD}IP        :{R} {YELLOW}{ip}{R}")
    print(f"  {BOLD}Protocolo :{R} {YELLOW}{'UDP' if udp else 'TCP'}{R}")
    print(f"  {BOLD}Portas    :{R} {YELLOW}{len(ports)} portas{R}")
    print(f"  {BOLD}Threads   :{R} {YELLOW}{threads}{R}")
    print(f"  {BOLD}Inicio    :{R} {DIM}{start.strftime('%Y-%m-%d %H:%M:%S')}{R}")
    print(f"  {BOLD}SO (TTL)  :{R} {MAGENTA}{guess_os(ip)}{R}")
    print(f"\n  {DIM}{'PORTA':<14} {'ESTADO':<16} {'SERVICO':<16} {'BANNER'}{R}")
    print(f"  {DIM}{'─'*60}{R}")

    results = []
    open_count = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        if udp:
            futs = {ex.submit(scan_port_udp, ip, p, timeout): p for p in ports}
        else:
            futs = {ex.submit(scan_port_tcp, ip, p, timeout, grab): p for p in ports}

        for fut in as_completed(futs):
            res = fut.result()
            if res:
                open_count += 1
                results.append(res)
                port = res["port"]
                state = res["state"]
                svc = res["service"]
                banner = (res["banner"] or "")[:50]
                tag = f"{port}/{res['proto']}"
                state_str = f"{GREEN}● open{R}" if state == "open" else f"{YELLOW}◐ {state}{R}"
                print(f"  {BOLD}{tag:<14}{R} {state_str:<25} {BLUE}{svc:<16}{R} {DIM}{banner}{R}")
                print_risk(port)
            elif verbose:
                port = futs[fut]
                svc = SERVICES.get(port, "")
                print(f"  {DIM}{str(port)+'/tcp':<14} ○ closed       {svc}{R}")

    results.sort(key=lambda x: x["port"])
    dur = (datetime.now() - start).total_seconds()

    print(f"\n  {DIM}{'─'*60}{R}")
    print(f"  {BOLD}Resultado :{R} {GREEN}{open_count}{R} porta(s) abertas de {YELLOW}{len(ports)}{R} escaneadas")
    print(f"  {BOLD}Duracao   :{R} {DIM}{dur:.2f}s{R}\n")

    if output:
        report = {
            "meta": {
                "target": target, "ip": ip, "hostname": hostname,
                "protocol": "udp" if udp else "tcp",
                "ports_scanned": len(ports), "open_ports": open_count,
                "start": start.isoformat(), "duration_s": round(dur, 2),
            },
            "results": results
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  {CYAN}[✓] Relatorio salvo em: {output}{R}\n")

    return results


# ─── CLI ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="pyscanner",
        description="PyScanner — Port Scanner para Segurança da Informação",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python scanner.py 192.168.1.1
  python scanner.py 192.168.1.1 -p 22,80,443
  python scanner.py 192.168.1.1 -p 1-1000 --threads 200
  python scanner.py alvo.com --top --udp
  python scanner.py 192.168.1.1 -p 1-65535 -o resultado.json
  python scanner.py 192.168.1.1 -v
        """
    )
    parser.add_argument("target",          help="Host alvo (IP ou hostname)")
    parser.add_argument("-p","--ports",    help="Portas: 80 | 80,443 | 1-1000")
    parser.add_argument("--top",           action="store_true", help="Escanear top portas conhecidas (~1000)")
    parser.add_argument("--udp",           action="store_true", help="Modo UDP (requer privilegios)")
    parser.add_argument("--threads",       type=int, default=100, help="Threads paralelas (padrao: 100)")
    parser.add_argument("--timeout",       type=float, default=1.0, help="Timeout por porta em segundos (padrao: 1.0)")
    parser.add_argument("--no-banner",     action="store_true", help="Desabilitar banner grabbing")
    parser.add_argument("-o","--output",   help="Salvar resultado em JSON")
    parser.add_argument("-v","--verbose",  action="store_true", help="Mostrar portas fechadas")
    args = parser.parse_args()

    if args.top:
        ports = TOP_PORTS
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = sorted({21,22,23,25,53,80,110,135,139,143,443,445,
                        1433,1521,3306,3389,4444,5432,5900,6379,8080,8443,27017}
                       | set(range(1, 1025)))

    run_scan(
        target=args.target,
        ports=ports,
        udp=args.udp,
        threads=args.threads,
        timeout=args.timeout,
        grab=not args.no_banner,
        output=args.output,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
