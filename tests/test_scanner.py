"""Testes das funções puras de scanner.py — parsing de saída do Windows
(ping, arp, ipconfig) e heurísticas de classificação — sem depender de
executar os comandos de verdade. Os textos de exemplo são modelados em cima
de saídas reais do Windows (PT-BR)."""
import struct

import scanner


# ---------- TTL / latência (parsing de `ping`) ----------

def test_parse_ttl_extracts_value():
    output = "Resposta de 192.168.1.1: bytes=32 tempo=1ms TTL=64"
    assert scanner._parse_ttl(output) == 64


def test_parse_ttl_is_case_insensitive():
    assert scanner._parse_ttl("Reply from 192.168.1.1: bytes=32 time=1ms ttl=128") == 128


def test_parse_ttl_returns_none_without_match():
    assert scanner._parse_ttl("Esgotado o tempo limite do pedido.") is None


def test_parse_latency_ms_pt_br():
    assert scanner._parse_latency_ms("Resposta de 192.168.1.1: bytes=32 tempo=5ms TTL=64") == 5.0


def test_parse_latency_ms_en():
    assert scanner._parse_latency_ms("Reply from 192.168.1.1: bytes=32 time=12.3ms TTL=64") == 12.3


def test_parse_latency_ms_returns_none_on_timeout():
    assert scanner._parse_latency_ms("Request timed out.") is None


# ---------- Estimativa de sistema operacional (TTL) ----------

def test_guess_os_none_ttl():
    assert scanner.guess_os(None) is None


def test_guess_os_linux_family():
    assert scanner.guess_os(64) == "Linux / macOS / Android / iOS"


def test_guess_os_windows():
    assert scanner.guess_os(128) == "Windows"


def test_guess_os_network_gear():
    assert scanner.guess_os(255) == "Equipamento de rede (roteador/switch)"


# ---------- Tabela ARP ----------

ARP_OUTPUT = """
Interface: 192.168.100.15 --- 0xb
  Endereço IP           Endereço físico       Tipo
  192.168.100.1         90-3f-ea-2c-a4-57     dinâmico
  192.168.100.10        a4-63-a1-1c-5a-0b     dinâmico
  192.168.100.255       ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  255.255.255.255       ff-ff-ff-ff-ff-ff     estático
"""


def test_parse_arp_table_extracts_real_hosts():
    table = scanner._parse_arp_table(ARP_OUTPUT)
    assert table == {
        "192.168.100.1": "90-3F-EA-2C-A4-57",
        "192.168.100.10": "A4-63-A1-1C-5A-0B",
    }


def test_parse_arp_table_excludes_broadcast_and_multicast():
    table = scanner._parse_arp_table(ARP_OUTPUT)
    assert "192.168.100.255" not in table
    assert "224.0.0.22" not in table
    assert "255.255.255.255" not in table


def test_is_real_host():
    assert scanner._is_real_host("192.168.1.10") is True
    assert scanner._is_real_host("192.168.1.255") is False
    assert scanner._is_real_host("192.168.1.0") is False
    assert scanner._is_real_host("224.0.0.251") is False
    assert scanner._is_real_host("255.255.255.255") is False


# ---------- Gateway padrão (ipconfig) ----------

IPCONFIG_OUTPUT = """Configuração de IP do Windows


Adaptador Ethernet Ethernet 2:

   Estado da mídia. . . . . . . . . . . . . .  : mídia desconectada

Adaptador de Rede sem Fio Wi-Fi:

   Sufixo DNS específico de conexão. . . . . . :
   Endereço IPv6 de link local . . . . . . . . : fe80::e9c:760c:7177:9e62%11
   Endereço IPv4. . . . . . . .  . . . . . . . : 192.168.100.15
   Máscara de Sub-rede . . . . . . . . . . . . : 255.255.255.0
   Gateway Padrão. . . . . . . . . . . . . . . : fe80::1%11
                                                 192.168.100.1

Adaptador Ethernet Conexão de Rede Bluetooth:

   Estado da mídia. . . . . . . . . . . . . .  : mídia desconectada
"""


def test_parse_gateway_finds_ipv4_on_continuation_line():
    # Caso real e comum: quando ha gateway IPv6 e IPv4 juntos, o IPv4 fica na
    # linha seguinte, nao na mesma linha do rotulo "Gateway Padrao".
    gateway = scanner._parse_gateway_from_ipconfig(IPCONFIG_OUTPUT, "192.168.100.15")
    assert gateway == "192.168.100.1"


def test_parse_gateway_returns_none_when_local_ip_absent():
    assert scanner._parse_gateway_from_ipconfig(IPCONFIG_OUTPUT, "10.0.0.5") is None


# ---------- hosts_in_subnet ----------

def test_hosts_in_subnet_covers_full_range():
    hosts = scanner.hosts_in_subnet("192.168.100.15")
    assert len(hosts) == 254
    assert hosts[0] == "192.168.100.1"
    assert hosts[-1] == "192.168.100.254"


# ---------- Classificação de dispositivo ----------

def test_classify_device_gateway_is_roteador():
    assert scanner.classify_device("Desconhecido", is_gateway=True) == "roteador"


def test_classify_device_local_is_computador():
    assert scanner.classify_device("Desconhecido", is_local=True) == "computador"


def test_classify_device_by_hostname_hint_printer():
    assert scanner.classify_device("EPSON-L3250") == "impressora"


def test_classify_device_by_hostname_hint_mobile():
    assert scanner.classify_device("Galaxy-S23") == "celular"


def test_classify_device_unknown_hostname_is_outro():
    assert scanner.classify_device("Desconhecido") == "outro"


def test_classify_device_known_hostname_falls_back_to_computador():
    assert scanner.classify_device("MEU-NOTEBOOK") == "computador"


def test_classify_device_uses_vendor_when_hostname_unhelpful(monkeypatch):
    monkeypatch.setattr(scanner, "_OUI_CACHE", {"A463A1": "TP-Link Corporation"})
    assert scanner.classify_device("Desconhecido", mac="A4:63:A1:11:22:33") == "roteador"


# ---------- Fabricante por MAC (OUI) ----------
# Observação: o 1º octeto usado nos MACs de teste abaixo tem o bit "locally
# administered" (0x02) desligado de propósito — é o mesmo bit que get_vendor
# checa para descartar MACs aleatórios/privados, então um MAC de teste mal
# escolhido (ex.: prefixo AA-BB-CC) falharia por engano nesse critério.

def test_get_vendor_known_prefix(monkeypatch):
    monkeypatch.setattr(scanner, "_OUI_CACHE", {"A463A1": "Fabricante Teste"})
    assert scanner.get_vendor("A4:63:A1:11:22:33") == "Fabricante Teste"


def test_get_vendor_unknown_prefix(monkeypatch):
    monkeypatch.setattr(scanner, "_OUI_CACHE", {})
    assert scanner.get_vendor("A4:63:A1:11:22:33") is None


def test_get_vendor_locally_administered_mac_has_no_vendor(monkeypatch):
    # 0x02 = bit "locally administered" ligado no 1º octeto — MAC gerado
    # aleatoriamente pelo dispositivo (recurso de privacidade), sem
    # fabricante rastreável, mesmo que o prefixo exista na base por coincidência.
    monkeypatch.setattr(scanner, "_OUI_CACHE", {"021122": "Não deveria aparecer"})
    assert scanner.get_vendor("02:11:22:33:44:55") is None


def test_get_vendor_none_for_unknown_mac():
    assert scanner.get_vendor("Desconhecido") is None
    assert scanner.get_vendor(None) is None


# ---------- Resolução de nome via mDNS (parsing de pacote DNS bruto) ----------

def test_build_dns_query_roundtrips_with_parse_dns_name():
    query = scanner._build_dns_query(["15", "100", "168", "192", "in-addr", "arpa"])
    # os primeiros 12 bytes sao o cabecalho fixo; o nome comeca no byte 12
    name, offset = scanner._parse_dns_name(query, 12)
    assert name == "15.100.168.192.in-addr.arpa"
    qtype, qclass = struct.unpack(">HH", query[offset:offset + 4])
    assert qtype == 12  # PTR
    assert qclass & 0x7FFF == 1  # IN (bit QU à parte)


def _build_mdns_ptr_response(question_qname_labels, answer_target_labels, answer_qname_labels=None):
    """Monta um pacote de resposta mDNS/DNS mínimo, com o nome da resposta
    comprimido via ponteiro (como o Windows realmente envia), para testar o
    parser sem precisar de rede de verdade."""
    answer_qname_labels = answer_qname_labels or question_qname_labels
    qname_bytes = b"".join(bytes([len(label)]) + label.encode() for label in question_qname_labels) + b"\x00"
    header = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 1, 0, 0)
    question = qname_bytes + struct.pack(">HH", 12, 1)
    if answer_qname_labels == question_qname_labels:
        answer_name = b"\xc0\x0c"  # ponteiro de compressão para o nome da pergunta (offset 12)
    else:
        answer_name = b"".join(bytes([len(label)]) + label.encode() for label in answer_qname_labels) + b"\x00"
    rdata = b"".join(bytes([len(label)]) + label.encode() for label in answer_target_labels) + b"\x00"
    answer = answer_name + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    return header + question + answer


def test_parse_mdns_ptr_response_extracts_hostname():
    qname_labels = ["15", "100", "168", "192", "in-addr", "arpa"]
    packet = _build_mdns_ptr_response(qname_labels, ["meu-notebook", "local"])
    hostname = scanner._parse_mdns_ptr_response(packet, "15.100.168.192.in-addr.arpa")
    assert hostname == "meu-notebook"


def test_parse_mdns_ptr_response_ignores_answer_for_different_query():
    # mDNS e multicast: o socket tambem recebe respostas de outros IPs.
    # Um PTR que nao responde exatamente ao nome perguntado deve ser ignorado,
    # senao associaria o hostname errado ao IP errado.
    packet = _build_mdns_ptr_response(
        ["9", "100", "168", "192", "in-addr", "arpa"],
        ["outro-aparelho", "local"],
    )
    hostname = scanner._parse_mdns_ptr_response(packet, "15.100.168.192.in-addr.arpa")
    assert hostname is None
