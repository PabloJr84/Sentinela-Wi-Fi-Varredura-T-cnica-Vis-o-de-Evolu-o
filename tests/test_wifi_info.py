"""Testes das funções puras de wifi_info.py — parsing de saída do `netsh` e
classificação de segurança — sem depender de ter uma placa Wi-Fi de verdade.
Os textos de exemplo são modelados em cima de saída real do
`netsh wlan show interfaces` / `show networks` em Windows PT-BR (com nomes de
rede genéricos, não os capturados de uma rede real)."""
import wifi_info


# ---------- Classificação de segurança ----------

def test_classify_security_wpa3():
    assert wifi_info.classify_security("WPA3-Personal") == ("segura", "WPA3")


def test_classify_security_wpa2():
    assert wifi_info.classify_security("WPA2-Personal") == ("segura", "WPA2")


def test_classify_security_open_pt_br():
    # No Windows em PT-BR o netsh reporta "Abrir" (verbo), não "Aberto"/"Aberta".
    level, label = wifi_info.classify_security("Abrir")
    assert level == "aberta"
    assert label == "Sem senha (rede aberta)"


def test_classify_security_open_en():
    level, _ = wifi_info.classify_security("Open")
    assert level == "aberta"


def test_classify_security_wep():
    level, label = wifi_info.classify_security("WEP")
    assert level == "quebrada"
    assert "WEP" in label


def test_classify_security_wpa_only_is_fraca():
    level, _ = wifi_info.classify_security("WPA-Personal")
    assert level == "fraca"


def test_classify_security_unknown_keeps_original_text():
    level, label = wifi_info.classify_security("802.1X")
    assert level == "desconhecida"
    assert label == "802.1X"


def test_classify_security_empty():
    assert wifi_info.classify_security("") == ("desconhecida", "Desconhecida")
    assert wifi_info.classify_security(None) == ("desconhecida", "Desconhecida")


# ---------- Parsing de campos "chave: valor" ----------

def test_parse_fields_basic():
    text = "Nome                   : Wi-Fi\nEstado                  : Conectado\n\nLinha sem dois pontos"
    fields = wifi_info._parse_fields(text)
    assert fields == {"Nome": "Wi-Fi", "Estado": "Conectado"}


def test_parse_fields_only_splits_on_first_colon():
    fields = wifi_info._parse_fields("Endereço físico       : 58:CD:C9:93:83:A3")
    assert fields["Endereço físico"] == "58:CD:C9:93:83:A3"


def test_first_skips_empty_values_and_falls_back():
    fields = {"Autenticação": "", "Authentication": "WPA2-Personal"}
    assert wifi_info._first(fields, "Autenticação", "Authentication") == "WPA2-Personal"


def test_first_returns_default_when_nothing_matches():
    assert wifi_info._first({}, "A", "B", default="—") == "—"


# ---------- Status da conexão Wi-Fi atual ----------

INTERFACE_FIELDS = {
    "Nome": "Wi-Fi",
    "Descrição": "Realtek 8821CE Wireless LAN 802.11ac PCI-E NIC",
    "Endereço físico": "58:CD:C9:93:83:A3",
    "Estado": "Conectado",
    "SSID": "MinhaCasa 5G",
    "AP BSSID": "90:3F:EA:2C:A4:64",
    "Banda": "5 GHz",
    "Canal": "36",
    "Tipo de rede": "Infraestrutura",
    "Tipo de rádio": "802.11ac",
    "Autenticação": "WPA2-Personal",
    "Criptografia": "CCMP",
    "Modo de conexão": "Conexão Automática",
    "Taxa de recepção (Mbps)": "433.3",
    "Taxa de transmissão (Mbps)": "433.3",
    "Sinal": "100%",
    "Rssi": "-41",
}


def test_build_wifi_status_maps_all_fields():
    status = wifi_info._build_wifi_status(INTERFACE_FIELDS)
    assert status == {
        "ssid": "MinhaCasa 5G",
        "bssid": "90:3F:EA:2C:A4:64",
        "signal_percent": "100",
        "rssi": "-41",
        "rx_mbps": "433.3",
        "tx_mbps": "433.3",
        "security": "WPA2-Personal",
        "security_level": "segura",
        "security_label": "WPA2",
        "cipher": "CCMP",
        "network_type": "Infraestrutura",
        "radio_type": "802.11ac",
        "connection_mode": "Conexão Automática",
        "band": "5 GHz",
        "channel": "36",
        "adapter": "Realtek 8821CE Wireless LAN 802.11ac PCI-E NIC",
        "adapter_mac": "58:CD:C9:93:83:A3",
    }


def test_build_wifi_status_none_when_no_ssid():
    assert wifi_info._build_wifi_status({}) is None


# ---------- Redes vizinhas ----------

NEARBY_OUTPUT = """Nome da interface: Wi-Fi
Há 2 redes visíveis no momento.

SSID 1 : Rede Um
    Tipo de rede            : Infraestrutura
    Autenticação            : WPA2-Personal
    Criptografia            : CCMP
    BSSID 1                 : aa:bb:cc:11:22:33
         Sinal             : 80%
         Tipo de Rádio         : 802.11ac
         Banda               : 5 GHz
         Canal            : 36
         Carga Bss:
             Estações Conectadas:         3
             Utilização do canal:        12 (4 %)

SSID 2 : Rede Aberta
    Tipo de rede            : Infraestrutura
    Autenticação            : Abrir
    Criptografia            : Nenhuma
    BSSID 1                 : dd:ee:ff:44:55:66
         Sinal             : 40%
         Tipo de Rádio         : 802.11n
         Banda               : 2,4 GHz
         Canal            : 6
"""


def test_parse_nearby_networks_count():
    assert len(wifi_info._parse_nearby_networks(NEARBY_OUTPUT)) == 2


def test_parse_nearby_networks_secure_entry():
    net = wifi_info._parse_nearby_networks(NEARBY_OUTPUT)[0]
    assert net["ssid"] == "Rede Um"
    assert net["bssid"] == "AA:BB:CC:11:22:33"
    assert net["signal_percent"] == 80
    assert net["channel"] == "36"
    assert net["security_level"] == "segura"
    assert net["connected_stations"] == 3
    assert net["channel_utilization_pct"] == 4


def test_parse_nearby_networks_open_entry_has_no_station_data():
    net = wifi_info._parse_nearby_networks(NEARBY_OUTPUT)[1]
    assert net["ssid"] == "Rede Aberta"
    assert net["bssid"] == "DD:EE:FF:44:55:66"
    assert net["security_level"] == "aberta"
    assert net["connected_stations"] is None
    assert net["channel_utilization_pct"] is None


def test_parse_nearby_networks_empty_output():
    assert wifi_info._parse_nearby_networks("Nome da interface: Wi-Fi\nHá 0 redes visíveis.") == []


# ---------- Senha salva ----------

def test_extract_key_content_pt_br():
    output = "Configurações do perfil\n    Conteúdo da Chave      : minhasenha123"
    assert wifi_info._extract_key_content(output) == "minhasenha123"


def test_extract_key_content_en():
    output = "Profile settings\n    Key Content            : mypassword1"
    assert wifi_info._extract_key_content(output) == "mypassword1"


def test_extract_key_content_absent():
    assert wifi_info._extract_key_content("Sem chave configurada") is None
