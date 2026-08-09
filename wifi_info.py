"""Informações da conexão Wi-Fi atual (SSID, sinal, velocidade, senha salva) via netsh."""
import ctypes
import re
import subprocess
from ctypes import wintypes


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8),
    ]


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", _GUID),
        ("strInterfaceDescription", ctypes.c_wchar * 256),
        ("isState", ctypes.c_uint),
    ]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1),
    ]


def trigger_wifi_scan():
    """Pede ao Windows para atualizar a lista de redes Wi-Fi vizinhas (scan ativo via
    wlanapi.dll — a mesma API que o gerenciador de Wi-Fi do Windows usa). Sem isso o
    `netsh wlan show networks` costuma devolver uma lista velha/em cache."""
    try:
        wlanapi = ctypes.WinDLL("wlanapi.dll")
    except OSError:
        return False

    handle = wintypes.HANDLE()
    negotiated_version = wintypes.DWORD()
    if wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated_version), ctypes.byref(handle)) != 0:
        return False

    try:
        p_iface_list = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
        if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(p_iface_list)) != 0:
            return False
        try:
            iface_list = p_iface_list.contents
            if iface_list.dwNumberOfItems > 0:
                guid = iface_list.InterfaceInfo[0].InterfaceGuid
                wlanapi.WlanScan(handle, ctypes.byref(guid), None, None, None)
                return True
            return False
        finally:
            wlanapi.WlanFreeMemory(p_iface_list)
    except Exception:
        return False
    finally:
        wlanapi.WlanCloseHandle(handle, None)


def _run_netsh(args):
    try:
        return subprocess.run(
            ["netsh"] + args, capture_output=True, text=True,
            encoding="utf-8", errors="ignore", timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).stdout
    except Exception:
        return ""


def _parse_fields(output):
    fields = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def _first(fields, *keys, default="?"):
    for key in keys:
        value = fields.get(key)
        if value:
            return value
    return default


def classify_security(security):
    """Classifica o nivel de protecao que a rede anuncia PUBLICAMENTE no beacon Wi-Fi
    (todo dispositivo por perto le isso para saber como tentar conectar). Isto NAO
    revela, obtem ou tenta quebrar nenhuma senha — e apenas o protocolo declarado."""
    if not security:
        return "desconhecida", "Desconhecida"
    s = security.lower()
    if "wpa3" in s:
        return "segura", "WPA3"
    if "wpa2" in s:
        return "segura", "WPA2"
    if "abrir" in s or "open" in s or "nenhum" in s or "none" in s:
        return "aberta", "Sem senha (rede aberta)"
    if "wep" in s:
        return "quebrada", "WEP (criptografia quebrada)"
    if "wpa" in s:
        return "fraca", "WPA (protocolo desatualizado)"
    return "desconhecida", security


def _build_wifi_status(fields):
    """Monta o dicionário de status a partir dos campos já parseados de
    `netsh wlan show interfaces` (função pura, testável sem depender do
    Windows). Retorna None se não houver Wi-Fi ativo."""
    ssid = fields.get("SSID")
    if not ssid:
        return None
    security = _first(fields, "Autenticação", "Authentication")
    security_level, security_label = classify_security(security)
    return {
        "ssid": ssid,
        "bssid": _first(fields, "BSSID do AP", "AP BSSID", "BSSID"),
        "signal_percent": _first(fields, "Sinal", "Signal", default="?").replace("%", "").strip(),
        "rssi": _first(fields, "Rssi", "RSSI"),
        "rx_mbps": _first(fields, "Taxa de recepção (Mbps)", "Receive rate (Mbps)"),
        "tx_mbps": _first(fields, "Taxa de transmissão (Mbps)", "Transmit rate (Mbps)"),
        "security": security,
        "security_level": security_level,
        "security_label": security_label,
        "cipher": _first(fields, "Criptografia", "Cipher"),
        "network_type": _first(fields, "Tipo de rede", "Network type"),
        "radio_type": _first(fields, "Tipo de rádio", "Radio type"),
        "connection_mode": _first(fields, "Modo de conexão", "Connection mode"),
        "band": _first(fields, "Banda", "Band"),
        "channel": _first(fields, "Canal", "Channel"),
        "adapter": _first(fields, "Descrição", "Description", default=""),
        "adapter_mac": _first(fields, "Endereço físico", "Physical address", default=""),
    }


def get_wifi_status():
    """Retorna dados da rede Wi-Fi atualmente conectada, ou None se nao houver Wi-Fi ativo."""
    fields = _parse_fields(_run_netsh(["wlan", "show", "interfaces"]))
    return _build_wifi_status(fields)


def _search(text, *patterns):
    for pattern in patterns:
        match = re.search(rf"{pattern}\s*:\s*(.+)", text)
        if match:
            return match.group(1).strip()
    return None


def _search_paren_pct(text, *patterns):
    """Extrai o valor percentual entre parenteses, ex: 'Utilizacao do canal: 12 (4 %)' -> 4."""
    for pattern in patterns:
        match = re.search(rf"{pattern}\s*:\s*\d+\s*\(\s*(\d+)\s*%\)", text)
        if match:
            return int(match.group(1))
    return None


def _parse_nearby_networks(output):
    """Extrai a lista de redes vizinhas de uma saída de
    `netsh wlan show networks mode=bssid` já decodificada (função pura,
    testável sem depender do Windows)."""
    networks = []
    ssid_blocks = re.split(r"\r?\nSSID\s+\d+\s*:[ \t]*", output)[1:]
    for block in ssid_blocks:
        lines = block.splitlines()
        ssid = lines[0].strip() if lines else ""

        network_type = _search(block, "Tipo de rede", "Network type") or "?"
        security = _search(block, r"Autentica[cç][aã]o", "Authentication") or "?"
        cipher = _search(block, "Criptografia", "Encryption") or "?"
        security_level, security_label = classify_security(security)

        bssid_blocks = re.split(r"\r?\n\s*BSSID\s+\d+\s*:\s*", block)[1:]
        for sub in bssid_blocks:
            bssid_match = re.match(r"([0-9a-fA-F:]{17})", sub.strip())
            if not bssid_match:
                continue
            signal_raw = _search(sub, "Sinal", "Signal") or "0%"
            stations = _search(sub, r"Esta[cç][oõ]es Conectadas", "Connected stations")
            networks.append({
                "ssid": ssid or "(rede oculta)",
                "bssid": bssid_match.group(1).upper(),
                "signal_percent": int(re.sub(r"\D", "", signal_raw) or 0),
                "radio_type": _search(sub, r"Tipo de R[aá]dio", "Radio type") or "?",
                "band": _search(sub, "Banda", "Band") or "?",
                "channel": _search(sub, "Canal", "Channel") or "?",
                "security": security,
                "security_level": security_level,
                "security_label": security_label,
                "network_type": network_type,
                "cipher": cipher,
                "connected_stations": int(stations) if stations and stations.isdigit() else None,
                "channel_utilization_pct": _search_paren_pct(
                    sub, r"Utiliza[cç][aã]o do canal", "Channel utilization"),
            })
    return networks


def get_nearby_networks():
    """Lista as redes Wi-Fi vizinhas detectadas pela placa deste notebook, com o maximo
    de detalhe tecnico que o Windows disponibiliza (sinal, canal, banda, seguranca,
    criptografia, tipo de radio, estacoes conectadas, uso do canal) — apenas o que o
    radio consegue "ouvir", sem qualquer tentativa de localizacao fisica."""
    output = _run_netsh(["wlan", "show", "networks", "mode=bssid"])
    if not output:
        return []
    return _parse_nearby_networks(output)


def _extract_key_content(output):
    """Extrai o conteúdo da chave de uma saída de
    `netsh wlan show profile ... key=clear` já decodificada — cobre tanto
    'Conteúdo da Chave' (PT-BR) quanto 'Key Content' (EN) (função pura,
    testável sem depender do Windows)."""
    match = re.search(r"Conte.do da Chave\s*:\s*(.+)", output)
    if not match:
        match = re.search(r"Key Content\s*:\s*(.+)", output)
    return match.group(1).strip() if match else None


def get_saved_password(ssid):
    """Recupera a senha salva no Windows para um perfil Wi-Fi ja conectado neste computador."""
    if not ssid:
        return None
    output = _run_netsh(["wlan", "show", "profile", f"name={ssid}", "key=clear"])
    return _extract_key_content(output)
