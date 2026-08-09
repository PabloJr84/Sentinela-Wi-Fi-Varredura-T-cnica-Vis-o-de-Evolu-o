# Sentinela Wi-Fi

Monitor de rede local para Windows: mostra IP, nome e MAC dos dispositivos
conectados, avisa quando um dispositivo novo entra na rede, exibe um mapa da
topologia da rede e o status da conexão Wi-Fi atual (SSID, sinal, velocidade,
senha salva, estabilidade).

## Requisitos

- Windows (usa `netsh`, `arp`, `ipconfig`, `nbtstat` e a API `wlanapi.dll`).
- Python 3.10+ com Tkinter (já vem no instalador padrão do python.org).
- Nenhuma dependência de terceiros para rodar — só biblioteca padrão.

## Rodando a partir do código-fonte

```
python main.py
```

## Desenvolvimento

```
pip install -r requirements-dev.txt
pytest
```

## Gerando o executável

```
pip install -r requirements-dev.txt
pyinstaller SentinelaWiFi.spec
```

Gera `dist/SentinelaWiFi.exe` (onefile, sem console, com ícone e a base de
fabricantes de rede — `oui_vendors.json` — já embutidos).

## Estrutura

| Arquivo | Responsabilidade |
|---|---|
| `main.py` | Interface (Tkinter), orquestração das threads de monitoramento e desenho dos painéis. |
| `scanner.py` | Descoberta de dispositivos na rede local: varredura ICMP, tabela ARP, resolução de hostname (DNS/mDNS/NetBIOS), classificação de dispositivo, varredura de portas. |
| `wifi_info.py` | Status da conexão Wi-Fi atual e redes vizinhas, via `netsh` e `wlanapi.dll`. |
| `oui_vendors.json` | Base de prefixos MAC → fabricante (projeto Wireshark), usada para identificar o fabricante de cada dispositivo. |
| `tests/` | Testes automatizados das funções de parsing e classificação (puras, sem depender do Windows real). |

## Dados salvos

O app grava o histórico de dispositivos conhecidos e o estado da rede em
`%APPDATA%\Sentinela Wi-Fi\` — nada é salvo dentro do repositório.
