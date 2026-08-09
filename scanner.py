"""Descoberta de dispositivos na rede local (varredura ICMP + tabela ARP)."""
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

PING_TIMEOUT_MS = 400
PING_WORKERS = 60
HOSTNAME_TIMEOUT_S = 1.2
HOSTNAME_WORKERS = 20
MDNS_TIMEOUT_S = 1.3
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def hosts_in_subnet(local_ip):
    """Retorna os 254 IPs do bloco /24 do IP local (suficiente para redes domésticas/pequenas)."""
    prefix = ".".join(local_ip.split(".")[:3])
    return [f"{prefix}.{i}" for i in range(1, 255)]


def _ping(ip):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip],
            capture_output=True, text=True, encoding="cp850", errors="ignore",
            timeout=2, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
        return int(match.group(1)) if match else None
    except Exception:
        return None


def ping_sweep(ips):
    """Retorna (ips_ativos, {ip: ttl}) — o TTL observado ajuda a estimar o sistema
    operacional de cada aparelho mais adiante."""
    alive = []
    ttls = {}
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
        futures = {executor.submit(_ping, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            ttl = future.result()
            if ttl is not None:
                alive.append(ip)
                ttls[ip] = ttl
    return alive, ttls


def guess_os(ttl):
    """Estima o sistema operacional pelo TTL inicial do ping — heuristica comum
    (Linux/macOS/Android/iOS partem de 64, Windows de 128, muitos roteadores de 255).
    Nao e uma identificacao exata, so uma aproximacao."""
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux / macOS / Android / iOS"
    if ttl <= 128:
        return "Windows"
    return "Equipamento de rede (roteador/switch)"


# Portas TCP comuns e o que costumam indicar quando abertas num dispositivo da
# rede domestica/pequena empresa — util para saber o que cada aparelho expoe
# (compartilhamento de arquivos, acesso remoto, camera, impressora, etc).
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet (inseguro)", 25: "SMTP",
    53: "DNS", 80: "HTTP (painel web)", 110: "POP3", 139: "SMB/NetBIOS",
    143: "IMAP", 443: "HTTPS (painel web)", 445: "SMB (compartilhamento)",
    554: "RTSP (câmera)", 631: "IPP (impressora)", 3389: "RDP (área de trabalho remota)",
    5000: "UPnP/NAS", 5357: "WSD", 8080: "HTTP alternativo",
    8443: "HTTPS alternativo", 9100: "Impressora de rede (JetDirect)", 62078: "iOS (lockdownd)",
}
PORT_SCAN_WORKERS = 100
PORT_SCAN_TIMEOUT_S = 0.35


def _check_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(ips, ports=None, timeout=PORT_SCAN_TIMEOUT_S):
    """Verifica quais portas TCP comuns estao abertas em cada IP da sua propria rede
    — mostra que tipo de servico cada aparelho esta expondo (arquivo compartilhado,
    acesso remoto, interface web, etc)."""
    ports = ports or COMMON_PORTS
    results = {ip: [] for ip in ips}
    with ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as executor:
        futures = {
            executor.submit(_check_port, ip, port, timeout): (ip, port)
            for ip in ips for port in ports
        }
        for future in as_completed(futures):
            ip, port = futures[future]
            if future.result():
                results[ip].append(port)
    for ip in results:
        results[ip].sort()
    return results


def get_arp_table():
    """Le a tabela ARP do sistema (populada apos o ping sweep) e retorna {ip: mac}."""
    table = {}
    try:
        output = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True,
            encoding="cp850", errors="ignore", timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).stdout
    except Exception:
        return table
    for match in re.finditer(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", output
    ):
        ip = match.group(1)
        if not _is_real_host(ip):
            continue
        table[ip] = match.group(2).upper()
    return table


def _is_real_host(ip):
    """Descarta enderecos de broadcast/multicast, que nao sao dispositivos de verdade."""
    if ip == "255.255.255.255" or ip.endswith(".255") or ip.endswith(".0"):
        return False
    first_octet = int(ip.split(".")[0])
    return first_octet < 224  # exclui faixas multicast (224-239) e reservada (240+)


def _resolve_hostname_dns(ip):
    try:
        socket.setdefaulttimeout(HOSTNAME_TIMEOUT_S)
        name, _, _ = socket.gethostbyaddr(ip)
        return name.split(".")[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _resolve_hostname_netbios(ip):
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip], capture_output=True, text=True,
            encoding="cp850", errors="ignore", timeout=2,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        match = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", result.stdout, re.MULTILINE)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def _build_dns_query(qname_labels, qtype=12, qclass=1, want_unicast_response=True):
    """Monta um pacote de consulta DNS/mDNS bruto (sem bibliotecas externas)."""
    header = struct.pack(">HHHHHH", 0, 0x0000, 1, 0, 0, 0)
    qname_bytes = b"".join(bytes([len(label)]) + label.encode("ascii", "ignore") for label in qname_labels) + b"\x00"
    qclass_field = qclass | (0x8000 if want_unicast_response else 0)  # bit "QU": pede resposta unicast
    return header + qname_bytes + struct.pack(">HH", qtype, qclass_field)


def _parse_dns_name(data, offset):
    """Decodifica um nome DNS (com suporte a compressão por ponteiro) a partir de offset."""
    labels = []
    jumped = False
    return_offset = offset
    hops = 0
    while hops < 64:
        hops += 1
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                return_offset = offset
            break
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                return_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(labels), return_offset


def _parse_mdns_ptr_response(data, expected_qname):
    """Extrai o registro PTR de uma resposta mDNS, mas SOMENTE se ele responde
    exatamente ao nome consultado — como mDNS e multicast, o socket tambem recebe
    trafego de outros aparelhos na rede, e aceitar qualquer PTR sem checar o nome
    associaria o hostname errado ao IP errado."""
    expected = expected_qname.rstrip(".").lower()
    try:
        _id, _flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        offset = 12
        for _ in range(qdcount):
            _qname, offset = _parse_dns_name(data, offset)
            offset += 4
        for _ in range(ancount):
            name, offset = _parse_dns_name(data, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 12 and name.rstrip(".").lower() == expected:  # PTR
                target, _ = _parse_dns_name(data, offset)
                if target:
                    return target.rstrip(".").split(".")[0]
            offset += rdlength
    except (struct.error, IndexError):
        pass
    return None


def _resolve_hostname_mdns(ip):
    """Pergunta via mDNS (Bonjour/Zeroconf) o nome .local do dono do IP — funciona em
    Smart TVs, Chromecast, impressoras, dispositivos Apple/Android/Linux e IoT em geral,
    diferente do NetBIOS que só responde em dispositivos Windows."""
    sock = None
    try:
        octets = ip.split(".")
        qname_labels = list(reversed(octets)) + ["in-addr", "arpa"]
        expected_qname = ".".join(qname_labels)
        query = _build_dns_query(qname_labels)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(MDNS_TIMEOUT_S)
        sock.sendto(query, (MDNS_GROUP, MDNS_PORT))

        deadline = time.monotonic() + MDNS_TIMEOUT_S
        while time.monotonic() < deadline:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            name = _parse_mdns_ptr_response(data, expected_qname)
            if name:
                return name
    except OSError:
        return None
    finally:
        if sock is not None:
            sock.close()
    return None


def resolve_hostname(ip):
    return (
        _resolve_hostname_dns(ip)
        or _resolve_hostname_mdns(ip)
        or _resolve_hostname_netbios(ip)
        or "Desconhecido"
    )


def ping_latency(ip, timeout_ms=1000):
    """Faz um ping simples e retorna a latencia em ms, ou None se nao houve resposta."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True, text=True, encoding="cp850", errors="ignore",
            timeout=timeout_ms / 1000 + 1, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        match = re.search(r"(?:tempo|time)[=<]\s*([\d.]+)\s*ms", result.stdout, re.IGNORECASE)
        if match:
            return float(match.group(1))
    except Exception:
        pass
    return None


PRINTER_HINTS = ("EPSON", "CANON", "BROTHER", "IMPRESSORA", "PRINTER")
MOBILE_HINTS = ("IPHONE", "ANDROID", "GALAXY", "XIAOMI", "REDMI", "MOTO")

# Base real de fabricantes por prefixo MAC (OUI), mantida pelo projeto Wireshark
# (https://www.wireshark.org/download/automated/data/manuf) e reprocessada em
# oui_vendors.json (prefixo de 6 hex -> nome do fabricante). Carregada uma unica vez.
_OUI_CACHE = None


def _oui_data_path():
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "oui_vendors.json")


def _load_oui_data():
    global _OUI_CACHE
    if _OUI_CACHE is None:
        try:
            with open(_oui_data_path(), "r", encoding="utf-8") as f:
                _OUI_CACHE = json.load(f)
        except (OSError, json.JSONDecodeError):
            _OUI_CACHE = {}
    return _OUI_CACHE


def get_vendor(mac):
    """Retorna o nome do fabricante a partir do MAC, ou None se nao identificado
    (inclui MACs aleatorios/privados, cada vez mais comuns em celulares)."""
    if not mac or mac == "Desconhecido":
        return None
    prefix = mac.upper().replace("-", "").replace(":", "")[:6]
    # bit "locally administered" (2o nibble do 1o octeto com valor 2/6/A/E) indica
    # MAC gerado aleatoriamente pelo dispositivo (recurso de privacidade), sem fabricante rastreavel
    try:
        first_octet = int(prefix[:2], 16)
        if first_octet & 0x02:
            return None
    except ValueError:
        return None
    return _load_oui_data().get(prefix)


# Palavras-chave (em minusculo) buscadas no nome do fabricante para estimar o tipo
# de dispositivo quando o hostname nao ajuda. Heuristica, nao garantia.
_VENDOR_KIND_KEYWORDS = (
    (("apple", "samsung", "xiaomi", "oppo", "vivo mobile", "oneplus", "realme",
      "motorola", "lg electronics", "sony mobile", "honor device", "asustek"), "celular"),
    (("hewlett", "hp inc", "canon", "epson", "brother industries"), "impressora"),
    (("amazon", "google", "nest", "sonos", "espressif", "tuya", "ring llc",
      "roku", "signify", "philips"), "iot"),
    (("tp-link", "ubiquiti", "netgear", "d-link", "mikrotik"), "roteador"),
)


def _kind_from_vendor(vendor_name):
    if not vendor_name:
        return None
    low = vendor_name.lower()
    for keywords, kind in _VENDOR_KIND_KEYWORDS:
        if any(k in low for k in keywords):
            return kind
    return None


def classify_device(hostname, mac=None, is_gateway=False, is_local=False):
    """Classifica o tipo de dispositivo por nome e, na falta dele, pelo fabricante (MAC)."""
    if is_gateway:
        return "roteador"
    if is_local:
        return "computador"

    name = hostname.upper()
    if name != "DESCONHECIDO":
        if any(hint in name for hint in PRINTER_HINTS) or name.startswith("HP"):
            return "impressora"
        if any(hint in name for hint in MOBILE_HINTS):
            return "celular"

    vendor_kind = _kind_from_vendor(get_vendor(mac))
    if vendor_kind:
        return vendor_kind

    return "outro" if name == "DESCONHECIDO" else "computador"


def get_default_gateway(local_ip):
    """Retorna o IP do roteador (gateway padrao) lendo o ipconfig do adaptador ativo."""
    try:
        output = subprocess.run(
            ["ipconfig"], capture_output=True, text=True,
            encoding="cp850", errors="ignore", timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).stdout
    except Exception:
        return None
    for block in re.split(r"\r?\n\r?\n", output):
        if local_ip not in block:
            continue
        lines = block.splitlines()
        for i, line in enumerate(lines):
            if "Gateway" not in line:
                continue
            # O IPv4 do gateway pode estar na mesma linha ou numa linha de
            # continuacao logo abaixo (comum quando ha gateway IPv6 e IPv4 juntos).
            for candidate in lines[i:i + 3]:
                match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", candidate)
                if match:
                    return match.group(1)
    return None


def scan_network(progress_callback=None):
    """Executa um scan completo da rede local e retorna uma lista de dispositivos."""
    def report(msg):
        if progress_callback:
            progress_callback(msg)

    local_ip = get_local_ip()
    ips = hosts_in_subnet(local_ip)

    report("Enviando pings...")
    alive_list, ttls = ping_sweep(ips)
    alive = set(alive_list)

    report("Lendo tabela ARP...")
    arp_table = get_arp_table()

    all_ips = sorted(alive | set(arp_table.keys()), key=lambda ip: int(ip.split(".")[-1]))
    if local_ip not in all_ips:
        all_ips.append(local_ip)
        all_ips.sort(key=lambda ip: int(ip.split(".")[-1]))

    report("Identificando roteador...")
    gateway_ip = get_default_gateway(local_ip)

    report("Resolvendo nomes de host...")
    hostnames = {}
    with ThreadPoolExecutor(max_workers=HOSTNAME_WORKERS) as executor:
        futures = {executor.submit(resolve_hostname, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            hostnames[futures[future]] = future.result()

    report("Verificando serviços abertos...")
    ports_by_ip = scan_ports(all_ips)

    devices = []
    for ip in all_ips:
        is_local = ip == local_ip
        is_gateway = ip == gateway_ip
        hostname = hostnames.get(ip, "Desconhecido")
        mac = arp_table.get(ip, "Desconhecido")
        open_ports = ports_by_ip.get(ip, [])
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": get_vendor(mac),
            "is_local": is_local,
            "is_gateway": is_gateway,
            "kind": classify_device(hostname, mac=mac, is_gateway=is_gateway, is_local=is_local),
            "os_guess": guess_os(ttls.get(ip)),
            "open_ports": [(port, COMMON_PORTS.get(port, "?")) for port in open_ports],
        })
    return devices


if __name__ == "__main__":
    for d in scan_network(progress_callback=print):
        print(d)
