"""Sentinela Wi-Fi — mostra IP, nome e MAC dos dispositivos conectados na rede local,
avisa quando um dispositivo novo entra na rede, exibe um mapa da topologia da rede e
o status da conexão Wi-Fi atual (SSID, sinal, velocidade, senha salva, estabilidade)."""
import csv
import hashlib
import json
import math
import os
import queue
import sys
import threading
import time
import tkinter as tk
import winsound
from collections import deque
from datetime import datetime
from tkinter import filedialog, ttk

import scanner
import wifi_info
from applog import APP_NAME, DATA_DIR, get_logger, log_once

log = get_logger()

DATA_FILE = os.path.join(DATA_DIR, "dispositivos_conhecidos.json")
NETWORK_META_FILE = os.path.join(DATA_DIR, "estado_rede.json")
DEFAULT_INTERVAL = 30
LATENCY_SAMPLE_SECONDS = 2
LATENCY_HISTORY = 90
WIFI_STATUS_REFRESH_SECONDS = 10
NEARBY_NETWORKS_REFRESH_SECONDS = 20
CLIPBOARD_CLEAR_SECONDS = 25  # tempo até apagar a senha copiada, como um gerenciador de senhas
RADAR_TICK_MS = 60
RADAR_SWEEP_DEG_PER_TICK = 3

GAUGE_SIZE = 46
GAUGE_THICKNESS = 5
GAUGE_TICK_MS = 30
GAUGE_EASE = 0.18  # fração da diferença percorrida a cada tick da animação
SPARKLINE_HISTORY = 30  # ~5 min de histórico nos cards de sinal/velocidade (a cada 10s)

# ---------- Paleta do Radar Wi-Fi (visual monocromático inspirado em HUDs de radar) ----------
RADAR_BG = "#050a05"
RADAR_RING = "#1f5c2f"
RADAR_GREEN = "#33cc4f"
RADAR_GREEN_BRIGHT = "#7dff8e"
RADAR_ACCENT = "#5ad8ff"
RADAR_TEXT = "#eafff0"

# ---------- Paleta (dataviz skill — tema escuro) ----------
BG_APP = "#0d0d0d"
SURFACE = "#1a1a19"
PANEL_ALT = "#232320"
INK_PRIMARY = "#ffffff"
INK_SECONDARY = "#c3c2b7"
INK_MUTED = "#898781"
GRIDLINE = "#2c2c2a"
BASELINE = "#383835"
ACCENT = "#3987e5"
ACCENT_HOVER = "#5aa0ec"
ACCENT_PRESSED = "#2a78d6"

CAT_COMPUTADOR = "#3987e5"
CAT_ROTEADOR = "#d95926"
CAT_IMPRESSORA = "#199e70"
CAT_CELULAR = "#c98500"
CAT_OUTRO = "#d55181"
CAT_IOT = "#008300"
STATUS_GOOD = "#0ca30c"
STATUS_WARNING = "#fab219"
STATUS_CRITICAL = "#d03b3b"

# Limiares (ms) de latência do ping até o roteador — hop local, não internet:
# valores normais de Wi-Fi doméstico ficam bem abaixo disso.
LATENCY_WARNING_MS = 40
LATENCY_CRITICAL_MS = 120
HEALTH_WINDOW = 30  # ~1 minuto de amostras (a cada 2s) usadas no diagnóstico

DEVICE_COLORS = {
    "computador": CAT_COMPUTADOR,
    "roteador": CAT_ROTEADOR,
    "impressora": CAT_IMPRESSORA,
    "celular": CAT_CELULAR,
    "iot": CAT_IOT,
    "outro": CAT_OUTRO,
}
DEVICE_LABELS = {
    "computador": "Computador",
    "roteador": "Roteador",
    "impressora": "Impressora",
    "celular": "Celular",
    "iot": "IoT / Casa inteligente",
    "outro": "Outro",
}
TRUST_LABELS = {
    "confiavel": "Confiável",
    "suspeito": "Suspeito",
    "novo": "Novo",
    "nao_verificado": "Não verificado",
}

# Portas comuns que, se abertas num dispositivo que não é este computador nem
# o roteador, valem um alerta na nota de saúde da rede (acesso remoto ou
# compartilhamento de arquivo exposto na rede local).
RISKY_OPEN_PORTS = {21, 23, 139, 445, 3389}

# Pesos de cada componente da nota de saúde da rede (soma 1.0 quando todos os
# dados estão disponíveis; um componente sem dado ainda é simplesmente
# ignorado e o restante é renormalizado).
HEALTH_WEIGHT_SECURITY = 0.35
HEALTH_WEIGHT_STABILITY = 0.30
HEALTH_WEIGHT_TRUST = 0.20
HEALTH_WEIGHT_PORTS = 0.15


def _fmt_mbps(value):
    try:
        return f"{float(value):.0f}"
    except (TypeError, ValueError):
        return str(value)


def _resource_path(filename):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, filename)


# ---------- Ícones vetoriais dos dispositivos (desenhados no Canvas, sem imagens) ----------
# Cada função recebe (canvas, x, y, s, color) — s é a "escala" (raio do nó no
# mapa) — e desenha um glifo simples em traço monolinha, no lugar das antigas
# siglas em texto (PC, RT, IMP...).

def _icon_computador(canvas, x, y, s, color):
    w, h = s * 0.95, s * 0.62
    canvas.create_rectangle(x - w / 2, y - h / 2 - 3, x + w / 2, y + h / 2 - 3, outline=color, width=1.6)
    canvas.create_line(x, y + h / 2 - 3, x, y + h / 2 + 4, fill=color, width=1.6)
    canvas.create_line(x - w * 0.3, y + h / 2 + 4, x + w * 0.3, y + h / 2 + 4, fill=color, width=1.6)


def _icon_roteador(canvas, x, y, s, color):
    w, h = s * 0.9, s * 0.42
    top = y - h * 0.1
    canvas.create_rectangle(x - w / 2, top, x + w / 2, top + h, outline=color, width=1.6)
    canvas.create_line(x - w * 0.22, top, x - w * 0.3, top - h * 1.5, fill=color, width=1.6)
    canvas.create_line(x + w * 0.22, top, x + w * 0.3, top - h * 1.5, fill=color, width=1.6)
    for dx in (-w * 0.22, 0, w * 0.22):
        canvas.create_oval(x + dx - 1.4, top + h * 0.55 - 1.4, x + dx + 1.4, top + h * 0.55 + 1.4,
                            outline=color, width=1.2)


def _icon_impressora(canvas, x, y, s, color):
    w = s * 0.85
    canvas.create_rectangle(x - w / 2, y - s * 0.05, x + w / 2, y + s * 0.4, outline=color, width=1.6)
    canvas.create_rectangle(x - w * 0.32, y - s * 0.42, x + w * 0.32, y - s * 0.05, outline=color, width=1.6)
    canvas.create_line(x - w * 0.28, y + s * 0.15, x + w * 0.28, y + s * 0.15, fill=color, width=1.3)


def _icon_celular(canvas, x, y, s, color):
    w, h = s * 0.46, s * 0.88
    canvas.create_rectangle(x - w / 2, y - h / 2, x + w / 2, y + h / 2, outline=color, width=1.6)
    canvas.create_line(x - w * 0.18, y + h / 2 - 4, x + w * 0.18, y + h / 2 - 4, fill=color, width=1.6)


def _icon_iot(canvas, x, y, s, color):
    r = s * 0.13
    canvas.create_oval(x - r, y - r, x + r, y + r, fill=color, outline="")
    for radius in (s * 0.32, s * 0.5):
        canvas.create_arc(x - radius, y - radius, x + radius, y + radius,
                           start=35, extent=110, style="arc", outline=color, width=1.4)


def _icon_outro(canvas, x, y, s, color):
    canvas.create_text(x, y, text="?", fill=color, font=("Segoe UI", 10, "bold"))


DEVICE_ICON_DRAWERS = {
    "computador": _icon_computador,
    "roteador": _icon_roteador,
    "impressora": _icon_impressora,
    "celular": _icon_celular,
    "iot": _icon_iot,
    "outro": _icon_outro,
}


# ---------- Funções puras de desenho (testáveis sem abrir uma janela) ----------

def _score_to_arc_extent(score):
    """Converte uma nota 0-100 no ângulo de varredura (graus) do arco do
    gauge de saúde da rede. Negativo porque o Canvas do Tkinter mede ângulos
    no sentido anti-horário a partir do eixo 3h, e o gauge preenche no
    sentido horário a partir do topo (90°)."""
    if score is None:
        return 0
    return -360 * max(0, min(100, score)) / 100


def _sparkline_points(history, width, height, y_max=None):
    """Calcula os pontos (x, y) em pixels de uma mini-tendência a partir de um
    histórico com possíveis lacunas (None) — função pura, sem desenhar nada,
    para poder ser testada sem depender de um Canvas de verdade."""
    values = [v for v in history if v is not None]
    if len(values) < 2:
        return []
    vmax = y_max if y_max is not None else (max(values) * 1.15 or 1)
    n = len(history)
    step_x = width / max(n - 1, 1)
    points = []
    for i, v in enumerate(history):
        if v is None:
            continue
        x = i * step_x
        y = height - (v / vmax) * height if vmax else height
        points.append((x, y))
    return points


def _configure_style():
    """Tema escuro unificado do app. Usa 'clam' (o único tema ttk totalmente
    recolorível no Windows — 'vista' delega a renderização ao Windows e ignora
    a maioria das cores customizadas)."""
    style = ttk.Style()
    style.theme_use("clam")

    style.configure(".", background=BG_APP, foreground=INK_PRIMARY,
                     fieldbackground=SURFACE, bordercolor=BASELINE,
                     darkcolor=SURFACE, lightcolor=SURFACE,
                     font=("Segoe UI", 9), borderwidth=1, focuscolor=ACCENT)

    style.configure("TFrame", background=BG_APP)
    style.configure("Header.TFrame", background=SURFACE)
    style.configure("Card.TFrame", background=SURFACE, bordercolor=BASELINE,
                     relief="solid", borderwidth=1)

    style.configure("TLabel", background=BG_APP, foreground=INK_PRIMARY)
    style.configure("Header.TLabel", background=SURFACE, foreground=INK_PRIMARY)
    style.configure("Card.TLabel", background=SURFACE, foreground=INK_PRIMARY)
    style.configure("CardMuted.TLabel", background=SURFACE, foreground=INK_MUTED, font=("Segoe UI", 8))
    style.configure("CardValue.TLabel", background=SURFACE, foreground=INK_PRIMARY, font=("Segoe UI", 13, "bold"))
    style.configure("Muted.TLabel", background=BG_APP, foreground=INK_MUTED, font=("Segoe UI", 8))
    style.configure("Status.TLabel", background=SURFACE, foreground=INK_SECONDARY, padding=(8, 4))

    style.configure("TButton", background=SURFACE, foreground=INK_PRIMARY,
                     bordercolor=BASELINE, padding=(10, 6), focusthickness=0)
    style.map("TButton",
              background=[("pressed", PANEL_ALT), ("active", PANEL_ALT)],
              foreground=[("disabled", INK_MUTED)])

    style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                     bordercolor=ACCENT, padding=(10, 6), focusthickness=0)
    style.map("Accent.TButton",
              background=[("pressed", ACCENT_PRESSED), ("active", ACCENT_HOVER)],
              bordercolor=[("pressed", ACCENT_PRESSED), ("active", ACCENT_HOVER)])

    style.configure("TEntry", fieldbackground=SURFACE, foreground=INK_PRIMARY,
                     bordercolor=BASELINE, insertcolor=INK_PRIMARY, padding=4)
    style.map("TEntry", fieldbackground=[("readonly", SURFACE)], foreground=[("readonly", INK_PRIMARY)])

    style.configure("TSpinbox", fieldbackground=SURFACE, foreground=INK_PRIMARY,
                     background=SURFACE, bordercolor=BASELINE, arrowcolor=INK_SECONDARY, padding=4)
    style.map("TSpinbox", fieldbackground=[("readonly", SURFACE)])

    style.configure("TNotebook", background=BG_APP, bordercolor=BASELINE, tabmargins=(0, 4, 0, 0))
    style.configure("TNotebook.Tab", background=SURFACE, foreground=INK_SECONDARY,
                     padding=(14, 7), bordercolor=BASELINE)
    style.map("TNotebook.Tab",
              background=[("selected", BG_APP)],
              foreground=[("selected", INK_PRIMARY)],
              expand=[("selected", (1, 1, 1, 0))])

    style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE,
                     foreground=INK_PRIMARY, bordercolor=BASELINE, rowheight=26, borderwidth=0)
    style.configure("Treeview.Heading", background=PANEL_ALT, foreground=INK_SECONDARY,
                     bordercolor=BASELINE, relief="flat", padding=(6, 6))
    style.map("Treeview.Heading", background=[("active", PANEL_ALT)])
    style.map("Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", "#ffffff")])

    style.configure("Vertical.TScrollbar", background=SURFACE, troughcolor=BG_APP,
                     bordercolor=BASELINE, arrowcolor=INK_SECONDARY)
    style.map("Vertical.TScrollbar", background=[("active", PANEL_ALT)])

    style.configure("TSeparator", background=BASELINE)

    style.configure("TCombobox", fieldbackground=SURFACE, background=SURFACE,
                     foreground=INK_PRIMARY, arrowcolor=INK_SECONDARY, bordercolor=BASELINE, padding=4)
    style.map("TCombobox",
              fieldbackground=[("readonly", SURFACE)],
              foreground=[("readonly", INK_PRIMARY)])
    root = style.master
    root.option_add("*TCombobox*Listbox.background", SURFACE)
    root.option_add("*TCombobox*Listbox.foreground", INK_PRIMARY)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")


class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} — Monitor de Rede")
        self.root.geometry("960x600")
        self.root.minsize(760, 460)

        self.monitoring = False
        self.monitor_thread = None
        self.event_queue = queue.Queue()
        self.known_devices = self._load_known_devices()
        self.network_meta = self._load_network_meta()
        self.last_devices = []
        self.suspect_macs = set()
        self._newly_seen_keys = set()
        self.search_var = tk.StringVar()
        self.kind_filter_var = tk.StringVar(value="Todos")

        self.latency_history = deque(maxlen=LATENCY_HISTORY)
        self._latency_points = []
        self.wifi_status = None
        self._last_ssid = None
        self._password_cache = None
        self.signal_history = deque(maxlen=SPARKLINE_HISTORY)
        self.speed_history = deque(maxlen=SPARKLINE_HISTORY)

        self._health_gauge_current = 0.0
        self._health_gauge_target = None
        self._health_gauge_color = INK_MUTED
        self._health_score_prev = None

        self.map_nodes = []
        self._map_tooltip_ip = None

        self.nearby_networks = []
        self._radar_nodes = []
        self._radar_angle = 0
        self._radar_tooltip_bssid = None
        self._radar_last_xy = (0, 0)

        self._build_ui()
        self.root.after(200, self._poll_queue)
        self.root.after(300, self._radar_tick)
        self.root.after(300, self._gauge_tick)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._start_background_services()

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self.root, style="Header.TFrame", padding=(12, 10))
        top.pack(fill="x")

        title = ttk.Label(top, text=APP_NAME, style="Header.TLabel", font=("Segoe UI", 11, "bold"))
        title.pack(side="left")

        # Nota única de saúde da rede: combina segurança do Wi-Fi, estabilidade
        # da conexão, confiança dos dispositivos e portas arriscadas expostas
        # num gauge sempre visível, em qualquer aba, com preenchimento animado
        # e seta de tendência em relação à última leitura.
        health_frame = ttk.Frame(top, style="Header.TFrame")
        health_frame.pack(side="right")
        self.health_gauge_canvas = tk.Canvas(health_frame, width=GAUGE_SIZE, height=GAUGE_SIZE,
                                              background=SURFACE, highlightthickness=0)
        self.health_gauge_canvas.pack(side="right")
        health_text = ttk.Frame(health_frame, style="Header.TFrame")
        health_text.pack(side="right", padx=(0, 8))
        ttk.Label(health_text, text="SAÚDE DA REDE", style="Header.TLabel",
                  foreground=INK_MUTED, font=("Segoe UI", 7)).pack(anchor="e")
        self.health_score_var = tk.StringVar(value="Coletando dados…")
        self.health_score_label = ttk.Label(health_text, textvariable=self.health_score_var,
                                             style="Header.TLabel", font=("Segoe UI", 9, "bold"))
        self.health_score_label.pack(anchor="e")

        self.local_ip_var = tk.StringVar(value="Rede: detectando...")
        ttk.Label(top, textvariable=self.local_ip_var, style="Header.TLabel",
                  foreground=INK_SECONDARY).pack(side="left", padx=(18, 0))

        ttk.Label(top, text="Intervalo (s):", style="Header.TLabel",
                  foreground=INK_SECONDARY).pack(side="left", padx=(24, 4))
        self.interval_var = tk.IntVar(value=DEFAULT_INTERVAL)
        ttk.Spinbox(top, from_=10, to=600, width=5, textvariable=self.interval_var).pack(side="left")

        self.toggle_btn = ttk.Button(top, text="Iniciar monitoramento", command=self._toggle_monitoring)
        self.toggle_btn.pack(side="left", padx=(12, 6))

        ttk.Button(top, text="Escanear agora", style="Accent.TButton",
                   command=self._scan_once).pack(side="left")

        tk.Frame(self.root, background=BASELINE, height=1).pack(fill="x")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        devices_tab = ttk.Frame(self.notebook)
        map_tab = ttk.Frame(self.notebook)
        wifi_tab = ttk.Frame(self.notebook)
        radar_tab = ttk.Frame(self.notebook)
        self.notebook.add(devices_tab, text="Dispositivos")
        self.notebook.add(map_tab, text="Mapa da Rede")
        self.notebook.add(wifi_tab, text="Rede Wi-Fi")
        self.notebook.add(radar_tab, text="Radar Wi-Fi")
        self.map_tab_frame = map_tab
        self.wifi_tab_frame = wifi_tab
        self.radar_tab_frame = radar_tab

        self._build_devices_tab(devices_tab)
        self._build_map_tab(map_tab)
        self._build_wifi_tab(wifi_tab)
        self._build_radar_tab(radar_tab)

        tk.Frame(self.root, background=BASELINE, height=1).pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Pronto. Clique em \"Escanear agora\" ou inicie o monitoramento.")
        ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel",
                  anchor="w").pack(fill="x", side="bottom")

    def _build_devices_tab(self, parent):
        summary = ttk.Frame(parent, padding=(4, 4, 4, 0))
        summary.pack(fill="x")
        summary_defs = [
            ("total", "DISPOSITIVOS"),
            ("trusted", "CONFIÁVEIS"),
            ("new", "NOVOS"),
            ("suspect", "SUSPEITOS"),
        ]
        self.device_summary_vars = {}
        self.device_summary_labels = {}
        for i, (key, title) in enumerate(summary_defs):
            summary.columnconfigure(i, weight=1)
            frame, var, label, _sparkline = self._make_stat_tile(summary, title)
            frame.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            self.device_summary_vars[key] = var
            self.device_summary_labels[key] = label

        toolbar = ttk.Frame(parent, padding=(4, 10, 4, 0))
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="Buscar:").pack(side="left")
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=22)
        search_entry.pack(side="left", padx=(4, 14))
        search_entry.bind("<KeyRelease>", lambda e: self._apply_device_filter())

        ttk.Label(toolbar, text="Tipo:").pack(side="left")
        kind_values = ["Todos"] + list(DEVICE_LABELS.values())
        kind_combo = ttk.Combobox(toolbar, textvariable=self.kind_filter_var, values=kind_values,
                                   state="readonly", width=20)
        kind_combo.pack(side="left", padx=(4, 14))
        kind_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_device_filter())

        ttk.Button(toolbar, text="Marcar/desmarcar confiável",
                   command=self._toggle_selected_trust).pack(side="left", padx=(0, 6))
        ttk.Button(toolbar, text="Exportar CSV", command=self._export_csv).pack(side="left")

        columns = ("ip", "hostname", "vendor", "kind", "mac", "status", "first_seen", "last_seen")
        headers = {
            "ip": "IP",
            "hostname": "Nome",
            "vendor": "Fabricante",
            "kind": "Tipo",
            "mac": "Endereço MAC",
            "status": "Confiança",
            "first_seen": "Visto pela 1ª vez",
            "last_seen": "Última vez visto",
        }
        widths = {"ip": 105, "hostname": 165, "vendor": 115, "kind": 90,
                  "mac": 125, "status": 100, "first_seen": 125, "last_seen": 125}

        paned = ttk.PanedWindow(parent, orient="vertical")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        tree_frame = ttk.Frame(paned)
        detail_frame = ttk.Frame(paned, style="Card.TFrame", padding=10)
        paned.add(tree_frame, weight=3)
        paned.add(detail_frame, weight=1)

        def _init_sash(event=None):
            total = paned.winfo_height()
            if total > 300:
                paned.sashpos(0, max(200, total - 190))
            paned.unbind("<Configure>")

        paned.bind("<Configure>", _init_sash)

        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor="w")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self._toggle_selected_trust())
        self.tree.bind("<<TreeviewSelect>>", self._on_device_tree_select)

        self.tree.tag_configure("odd", background=SURFACE)
        self.tree.tag_configure("even", background=PANEL_ALT)
        self.tree.tag_configure("trust_novo", background="#3a2f10", foreground="#ffd479")
        self.tree.tag_configure("trust_suspeito", background="#3a1414", foreground="#ff9d9d")

        ttk.Label(detail_frame, text="DETALHES DO DISPOSITIVO", style="CardMuted.TLabel").pack(anchor="w")
        self.device_detail_var = tk.StringVar(
            value="Selecione um dispositivo na tabela acima para ver todos os detalhes "
                  "(sistema operacional estimado, serviços/portas abertas etc).")
        ttk.Label(detail_frame, textvariable=self.device_detail_var, style="Card.TLabel",
                  font=("Consolas", 8), justify="left", wraplength=900).pack(anchor="w", pady=(4, 0))

    def _build_map_tab(self, parent):
        legend = ttk.Frame(parent, padding=(8, 6))
        legend.pack(fill="x", side="bottom")
        for kind, label in DEVICE_LABELS.items():
            self._legend_swatch(legend, DEVICE_COLORS[kind], label)

        self.map_canvas = tk.Canvas(parent, background=SURFACE, highlightthickness=0)
        self.map_canvas.pack(fill="both", expand=True, padx=4, pady=(4, 0))
        self.map_canvas.bind("<Configure>", lambda e: self._draw_map(self.last_devices))
        self.map_canvas.bind("<Motion>", self._on_map_hover)
        self.map_canvas.bind("<Leave>", lambda e: self._clear_map_tooltip())

    def _build_wifi_tab(self, parent):
        container = ttk.Frame(parent, padding=8)
        container.pack(fill="both", expand=True)

        tiles_frame = ttk.Frame(container)
        tiles_frame.pack(fill="x")
        tile_defs = [
            ("ssid", "REDE (SSID)"),
            ("security", "SEGURANÇA"),
            ("signal", "SINAL"),
            ("channel", "CANAL / BANDA"),
            ("speed", "VELOCIDADE"),
        ]
        self.wifi_tiles = {}
        self.wifi_sparklines = {}
        for i, (key, title) in enumerate(tile_defs):
            tiles_frame.columnconfigure(i, weight=1)
            frame, var, _label, sparkline = self._make_stat_tile(
                tiles_frame, title, with_sparkline=key in ("signal", "speed"))
            frame.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            self.wifi_tiles[key] = var
            if sparkline is not None:
                self.wifi_sparklines[key] = sparkline
                sparkline.bind("<Configure>", lambda e, k=key: self._draw_wifi_sparkline(k))

        tiles_frame2 = ttk.Frame(container)
        tiles_frame2.pack(fill="x", pady=(6, 0))
        tile_defs2 = [
            ("bssid", "BSSID DO ROTEADOR"),
            ("rssi", "RSSI"),
            ("cipher", "CRIPTOGRAFIA"),
            ("radio_type", "PADRÃO WI-FI"),
            ("connection_mode", "MODO DE CONEXÃO"),
        ]
        for i, (key, title) in enumerate(tile_defs2):
            tiles_frame2.columnconfigure(i, weight=1)
            frame, var, _label, _sparkline = self._make_stat_tile(tiles_frame2, title)
            frame.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            self.wifi_tiles[key] = var

        self.adapter_var = tk.StringVar(value="")
        ttk.Label(container, textvariable=self.adapter_var, foreground=INK_MUTED,
                  font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 0))

        pw_frame = ttk.Frame(container, padding=(0, 10, 0, 6))
        pw_frame.pack(fill="x")
        ttk.Label(pw_frame, text="Senha desta rede:").pack(side="left")
        self.password_var = tk.StringVar(value="")
        self.password_entry = ttk.Entry(pw_frame, textvariable=self.password_var, show="•", width=28, state="readonly")
        self.password_entry.pack(side="left", padx=8)
        self.show_pw_btn = ttk.Button(pw_frame, text="Mostrar", command=self._toggle_password)
        self.show_pw_btn.pack(side="left")
        ttk.Button(pw_frame, text="Copiar", command=self._copy_password).pack(side="left", padx=(6, 0))

        chart_header = ttk.Frame(container)
        chart_header.pack(fill="x", pady=(8, 2))
        ttk.Label(chart_header, text="Estabilidade da conexão (ping até o roteador)",
                  font=("Segoe UI", 9, "bold")).pack(side="left")
        self._legend_swatch(chart_header, CAT_COMPUTADOR, "Latência (ms)")
        self._legend_swatch(chart_header, STATUS_WARNING, "Sinal de alerta")
        self._legend_swatch(chart_header, STATUS_CRITICAL, "Perda de pacote")

        chart_row = ttk.Frame(container)
        chart_row.pack(fill="both", expand=True)

        self.latency_canvas = tk.Canvas(chart_row, background=SURFACE, highlightthickness=0, height=220)
        self.latency_canvas.pack(side="left", fill="both", expand=True)
        self.latency_canvas.bind("<Configure>", lambda e: self._draw_latency_chart())
        self.latency_canvas.bind("<Motion>", self._on_latency_hover)
        self.latency_canvas.bind("<Leave>", lambda e: self._draw_latency_chart())

        health_frame = ttk.Frame(chart_row, style="Card.TFrame", padding=12, width=220)
        health_frame.pack(side="right", fill="y", padx=(8, 0))
        health_frame.pack_propagate(False)
        ttk.Label(health_frame, text="DIAGNÓSTICO DA CONEXÃO", style="CardMuted.TLabel").pack(anchor="w")
        self.health_verdict_var = tk.StringVar(value="—")
        self.health_verdict_label = ttk.Label(health_frame, textvariable=self.health_verdict_var,
                                               style="CardValue.TLabel", font=("Segoe UI", 18, "bold"))
        self.health_verdict_label.pack(anchor="w", pady=(4, 8))
        self.health_detail_var = tk.StringVar(value="Coletando amostras…")
        ttk.Label(health_frame, textvariable=self.health_detail_var, style="CardMuted.TLabel",
                  wraplength=190, justify="left").pack(anchor="w")

    def _make_stat_tile(self, parent, title, with_sparkline=False):
        frame = ttk.Frame(parent, padding=(10, 8), style="Card.TFrame")
        ttk.Label(frame, text=title, style="CardMuted.TLabel").pack(anchor="w")
        value_var = tk.StringVar(value="—")
        value_label = ttk.Label(frame, textvariable=value_var, style="CardValue.TLabel")
        value_label.pack(anchor="w")
        sparkline_canvas = None
        if with_sparkline:
            sparkline_canvas = tk.Canvas(frame, height=22, background=SURFACE, highlightthickness=0)
            sparkline_canvas.pack(fill="x", pady=(6, 0))
        return frame, value_var, value_label, sparkline_canvas

    def _draw_wifi_sparkline(self, key):
        """Redesenha a mini-tendência de um card da aba Wi-Fi (sinal ou
        velocidade) a partir do histórico recente — dá pra ver a tendência
        sem precisar abrir o gráfico de latência."""
        canvas = self.wifi_sparklines.get(key)
        if canvas is None:
            return
        canvas.delete("all")
        history, y_max = {
            "signal": (self.signal_history, 100),
            "speed": (self.speed_history, None),
        }[key]
        width = canvas.winfo_width() or 120
        height = canvas.winfo_height() or 22
        points = _sparkline_points(list(history), width, height, y_max=y_max)
        if len(points) < 2:
            return
        flat = [c for p in points for c in p]
        canvas.create_line(*flat, fill=ACCENT, width=1.5, capstyle="round", joinstyle="round")
        lx, ly = points[-1]
        canvas.create_oval(lx - 2, ly - 2, lx + 2, ly + 2, fill=ACCENT, outline="")

    def _legend_swatch(self, parent, color, text):
        frame = ttk.Frame(parent)
        frame.pack(side="left", padx=(16, 0))
        dot = tk.Frame(frame, width=10, height=10, background=color)
        dot.pack(side="left", pady=2)
        dot.pack_propagate(False)
        ttk.Label(frame, text=text, foreground=INK_SECONDARY, font=("Segoe UI", 8)).pack(side="left", padx=(4, 0))

    def _build_radar_tab(self, parent):
        paned = ttk.PanedWindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        radar_side = ttk.Frame(paned)
        list_side = ttk.Frame(paned, style="Card.TFrame", padding=8)
        paned.add(radar_side, weight=3)
        paned.add(list_side, weight=1)

        caption = ttk.Frame(radar_side, padding=(4, 6))
        caption.pack(fill="x", side="bottom")
        ttk.Label(
            caption,
            text="Distância no gráfico é aproximada, calculada pela intensidade do sinal captado por "
                 "este notebook — não é uma localização física real. Ângulo é apenas ilustrativo.",
            foreground=INK_MUTED, font=("Segoe UI", 8), wraplength=700, justify="left",
        ).pack(anchor="w")
        self._legend_swatch(caption, RADAR_ACCENT, "Sua rede")
        self._legend_swatch(caption, RADAR_GREEN, "Segura (WPA2/WPA3)")
        self._legend_swatch(caption, STATUS_WARNING, "Protocolo fraco (WPA)")
        self._legend_swatch(caption, STATUS_CRITICAL, "Sem senha / WEP")

        self.radar_canvas = tk.Canvas(radar_side, background=RADAR_BG, highlightthickness=0)
        self.radar_canvas.pack(fill="both", expand=True)
        self.radar_canvas.bind("<Configure>", lambda e: self._draw_radar())
        self.radar_canvas.bind("<Motion>", self._on_radar_hover)
        self.radar_canvas.bind("<Leave>", self._on_radar_leave)

        self.nearby_count_var = tk.StringVar(value="REDES ENCONTRADAS")
        ttk.Label(list_side, textvariable=self.nearby_count_var, style="CardMuted.TLabel").pack(anchor="w", pady=(0, 6))

        columns = ("ssid", "signal", "channel", "security")
        headers = {"ssid": "Rede", "signal": "Sinal", "channel": "Canal", "security": "Segurança"}
        widths = {"ssid": 130, "signal": 50, "channel": 50, "security": 110}
        self.nearby_tree = ttk.Treeview(list_side, columns=columns, show="headings", height=10)
        for col in columns:
            self.nearby_tree.heading(col, text=headers[col])
            self.nearby_tree.column(col, width=widths[col], anchor="w")
        self.nearby_tree.pack(fill="both", expand=False)
        self.nearby_tree.tag_configure("own", background="#12283d", foreground="#9cc9ff")
        self.nearby_tree.tag_configure("insecure_critical", background="#3a1414", foreground="#ff9d9d")
        self.nearby_tree.tag_configure("insecure_weak", background="#3a2f10", foreground="#ffd479")
        self.nearby_tree.bind("<<TreeviewSelect>>", self._on_nearby_tree_select)

        ttk.Separator(list_side, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(list_side, text="DETALHES", style="CardMuted.TLabel").pack(anchor="w")
        self.nearby_detail_var = tk.StringVar(value="Selecione uma rede na lista acima.")
        ttk.Label(list_side, textvariable=self.nearby_detail_var, style="Card.TLabel",
                  font=("Consolas", 8), wraplength=260, justify="left").pack(anchor="w", pady=(4, 0))

    # ---------- Persistência ----------
    def _load_known_devices(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                log.exception("Arquivo de dispositivos conhecidos corrompido/ilegível — começando do zero: %s", DATA_FILE)
                return {}
        return {}

    def _save_known_devices(self):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(self.known_devices, f, ensure_ascii=False, indent=2)
        except OSError:
            log.exception("Falha ao salvar dispositivos conhecidos em %s.", DATA_FILE)

    def _load_network_meta(self):
        if os.path.exists(NETWORK_META_FILE):
            try:
                with open(NETWORK_META_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                log.exception("Arquivo de estado da rede corrompido/ilegível — começando do zero: %s", NETWORK_META_FILE)
                return {}
        return {}

    def _save_network_meta(self):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(NETWORK_META_FILE, "w", encoding="utf-8") as f:
                json.dump(self.network_meta, f, ensure_ascii=False, indent=2)
        except OSError:
            log.exception("Falha ao salvar estado da rede em %s.", NETWORK_META_FILE)

    # ---------- Controle de monitoramento (varredura de dispositivos) ----------
    def _toggle_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.toggle_btn.config(text="Iniciar monitoramento")
            self.status_var.set("Monitoramento parado.")
        else:
            self.monitoring = True
            self.toggle_btn.config(text="Parar monitoramento")
            if not (self.monitor_thread and self.monitor_thread.is_alive()):
                self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
                self.monitor_thread.start()

    def _scan_once(self):
        threading.Thread(target=self._run_single_scan, daemon=True).start()

    def _monitor_loop(self):
        while self.monitoring:
            self._run_single_scan()
            for _ in range(self.interval_var.get() * 10):
                if not self.monitoring:
                    break
                time.sleep(0.1)

    def _run_single_scan(self):
        self.event_queue.put(("status", "Escaneando rede..."))
        try:
            devices = scanner.scan_network(
                progress_callback=lambda msg: self.event_queue.put(("status", msg))
            )
            self.event_queue.put(("result", devices))
        except Exception as exc:
            log.exception("Falha durante a varredura de rede.")
            self.event_queue.put(("status", f"Erro no scan: {exc}"))

    # ---------- Serviços contínuos (SSID/senha/velocidade, latência e redes vizinhas) ----------
    def _start_background_services(self):
        threading.Thread(target=self._wifi_status_loop, daemon=True).start()
        threading.Thread(target=self._latency_loop, daemon=True).start()
        threading.Thread(target=self._nearby_loop, daemon=True).start()

    def _wifi_status_loop(self):
        while True:
            try:
                status = wifi_info.get_wifi_status()
            except Exception:
                log_once(log, "wifi_status_loop_failed", "Falha ao consultar status do Wi-Fi.", exc_info=True)
                status = None
            self.event_queue.put(("wifi_status", status))
            time.sleep(WIFI_STATUS_REFRESH_SECONDS)

    def _latency_loop(self):
        gateway_ip = None
        while True:
            if not gateway_ip:
                try:
                    gateway_ip = scanner.get_default_gateway(scanner.get_local_ip())
                except Exception:
                    log_once(log, "latency_loop_gateway_failed",
                             "Falha ao identificar o gateway para medir latência.", exc_info=True)
                    gateway_ip = None
            latency = scanner.ping_latency(gateway_ip) if gateway_ip else None
            self.event_queue.put(("latency", latency))
            time.sleep(LATENCY_SAMPLE_SECONDS)

    def _nearby_loop(self):
        while True:
            try:
                wifi_info.trigger_wifi_scan()
                time.sleep(2.5)
                networks = wifi_info.get_nearby_networks()
            except Exception:
                log_once(log, "nearby_loop_failed", "Falha ao listar redes Wi-Fi vizinhas.", exc_info=True)
                networks = []
            self.event_queue.put(("nearby", networks))
            time.sleep(NEARBY_NETWORKS_REFRESH_SECONDS)

    # ---------- Fila de eventos (thread-safe) ----------
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "status":
                    self.status_var.set(payload)
                elif kind == "result":
                    self._handle_scan_result(payload)
                elif kind == "wifi_status":
                    self._handle_wifi_status(payload)
                elif kind == "latency":
                    self._handle_latency(payload)
                elif kind == "nearby":
                    self.nearby_networks = payload
                    self._refresh_nearby_tree(payload)
        except queue.Empty:
            pass
        self.root.after(200, self._poll_queue)

    def _handle_scan_result(self, devices):
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        local_ip = next((d["ip"] for d in devices if d["is_local"]), None)
        if local_ip:
            self.local_ip_var.set(f"Rede local: {local_ip}")

        alerts, suspect_macs = self._check_security_anomalies(devices)
        self.suspect_macs = suspect_macs

        new_devices = []
        newly_seen_keys = set()
        for d in devices:
            key = d["mac"] if d["mac"] != "Desconhecido" else d["ip"]
            if key not in self.known_devices:
                self.known_devices[key] = {"first_seen": now}
                new_devices.append(d)
                newly_seen_keys.add(key)
            self.known_devices[key]["last_seen"] = now
            self.known_devices[key]["ip"] = d["ip"]
            if d["hostname"] != "Desconhecido":
                self.known_devices[key]["hostname"] = d["hostname"]
            if d["is_local"] or d["is_gateway"]:
                self.known_devices[key]["trusted"] = True

        self._newly_seen_keys = newly_seen_keys
        self._save_known_devices()
        self.last_devices = devices
        self._apply_device_filter()
        self._draw_map(devices)
        self._update_device_summary()
        self._update_network_health()
        self.status_var.set(f"Última verificação: {now} — {len(devices)} dispositivo(s) encontrado(s).")

        if new_devices:
            self._notify_new_devices(new_devices)
        if alerts:
            self._notify_security_alerts(alerts)

    def _update_device_summary(self):
        """Atualiza os cards-resumo no topo da aba Dispositivos — total,
        confiáveis, novos e suspeitos — para dar o panorama antes de mergulhar
        na tabela detalhada."""
        counts = {"total": len(self.last_devices), "trusted": 0, "new": 0, "suspect": 0}
        status_to_key = {"confiavel": "trusted", "novo": "new", "suspeito": "suspect"}
        for d in self.last_devices:
            key = status_to_key.get(self._device_trust_status(d))
            if key:
                counts[key] += 1

        for key, value in counts.items():
            self.device_summary_vars[key].set(str(value))

        self.device_summary_labels["suspect"].configure(
            foreground=STATUS_CRITICAL if counts["suspect"] else INK_PRIMARY)
        self.device_summary_labels["new"].configure(
            foreground=STATUS_WARNING if counts["new"] else INK_PRIMARY)

    def _device_key(self, d):
        return d["mac"] if d["mac"] != "Desconhecido" else d["ip"]

    def _device_trust_status(self, d):
        key = self._device_key(d)
        if d["mac"] in self.suspect_macs:
            return "suspeito"
        if self.known_devices.get(key, {}).get("trusted"):
            return "confiavel"
        if key in self._newly_seen_keys:
            return "novo"
        return "nao_verificado"

    def _apply_device_filter(self):
        query = self.search_var.get().strip().lower()
        kind_filter = self.kind_filter_var.get()
        filtered = []
        for d in self.last_devices:
            if kind_filter and kind_filter != "Todos" and DEVICE_LABELS.get(d.get("kind"), "Outro") != kind_filter:
                continue
            if query:
                haystack = f"{d['hostname']} {d['ip']} {d['mac']} {d.get('vendor') or ''}".lower()
                if query not in haystack:
                    continue
            filtered.append(d)
        self._refresh_tree(filtered)

    def _refresh_tree(self, devices):
        selected = self.tree.selection()
        selected_ip = selected[0] if selected else None
        self.tree.delete(*self.tree.get_children())
        for i, d in enumerate(devices):
            key = self._device_key(d)
            info = self.known_devices.get(key, {})
            status = self._device_trust_status(d)
            tags = ["even" if i % 2 == 0 else "odd"]
            if status in ("novo", "suspeito"):
                tags.append(f"trust_{status}")
            self.tree.insert("", "end", iid=d["ip"], values=(
                d["ip"],
                d["hostname"] + (" (este computador)" if d["is_local"] else ""),
                d.get("vendor") or "—",
                DEVICE_LABELS.get(d.get("kind"), "Outro"),
                d["mac"],
                TRUST_LABELS.get(status, status),
                info.get("first_seen", ""),
                info.get("last_seen", ""),
            ), tags=tags)
        if selected_ip and self.tree.exists(selected_ip):
            self.tree.selection_set(selected_ip)
        else:
            self.device_detail_var.set(
                "Selecione um dispositivo na tabela acima para ver todos os detalhes "
                "(sistema operacional estimado, serviços/portas abertas etc).")

    def _on_device_tree_select(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        ip = selection[0]
        device = next((d for d in self.last_devices if d["ip"] == ip), None)
        if not device:
            return
        self.device_detail_var.set(self._format_device_details(device))

    def _format_device_details(self, d):
        key = self._device_key(d)
        info = self.known_devices.get(key, {})
        status = self._device_trust_status(d)
        lines = [
            f"IP: {d['ip']}    MAC: {d['mac']}",
            f"Nome: {d['hostname']}" + (" (este computador)" if d["is_local"] else ""),
            f"Fabricante: {d.get('vendor') or 'desconhecido (MAC privado/aleatório)'}",
            f"Tipo: {DEVICE_LABELS.get(d.get('kind'), 'Outro')}"
            + ("  •  Roteador da rede" if d.get("is_gateway") else ""),
            f"Confiança: {TRUST_LABELS.get(status, status)}",
            f"Sistema operacional (estimado): {d.get('os_guess') or 'não identificado'}",
            f"Visto pela 1ª vez: {info.get('first_seen', '?')}    "
            f"Última vez visto: {info.get('last_seen', '?')}",
        ]
        ports = d.get("open_ports") or []
        if ports:
            services = "  •  ".join(f"{port} ({label})" for port, label in ports)
            lines.append(f"Serviços/portas abertas: {services}")
        else:
            lines.append("Serviços/portas abertas: nenhuma porta comum encontrada aberta")
        return "\n".join(lines)

    def _toggle_selected_trust(self):
        selection = self.tree.selection()
        if not selection:
            self.status_var.set("Selecione um ou mais dispositivos na lista para marcar/desmarcar confiança.")
            return
        devices_by_ip = {d["ip"]: d for d in self.last_devices}
        for ip in selection:
            d = devices_by_ip.get(ip)
            if not d:
                continue
            key = self._device_key(d)
            info = self.known_devices.setdefault(key, {})
            info["trusted"] = not info.get("trusted", False)
        self._save_known_devices()
        self._apply_device_filter()

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="dispositivos_sentinela_wifi.csv",
            title="Exportar lista de dispositivos",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["IP", "Nome", "Fabricante", "Tipo", "MAC", "Confiança",
                                  "Sistema Operacional (estimado)", "Portas/Serviços Abertos",
                                  "Visto pela 1a vez", "Ultima vez visto"])
                for d in self.last_devices:
                    key = self._device_key(d)
                    info = self.known_devices.get(key, {})
                    ports = ", ".join(f"{port} ({label})" for port, label in (d.get("open_ports") or []))
                    writer.writerow([
                        d["ip"], d["hostname"], d.get("vendor") or "",
                        DEVICE_LABELS.get(d.get("kind"), "Outro"), d["mac"],
                        TRUST_LABELS.get(self._device_trust_status(d), ""),
                        d.get("os_guess") or "", ports,
                        info.get("first_seen", ""), info.get("last_seen", ""),
                    ])
            self.status_var.set(f"Lista exportada: {path}")
        except OSError as exc:
            log.exception("Falha ao exportar CSV para %s.", path)
            self.status_var.set(f"Erro ao exportar CSV: {exc}")

    # ---------- Detecção de anomalias (possíveis invasores) ----------
    def _check_security_anomalies(self, devices):
        """Heurísticas baseadas no que já sabemos da rede — não é uma garantia de
        detectar um invasor sofisticado, mas pega os sinais clássicos de ataque
        de ARP na rede local: o roteador "trocando" de MAC do nada, ou um mesmo
        MAC respondendo por vários IPs ao mesmo tempo."""
        alerts = []
        suspect_macs = set()

        gateway = next((d for d in devices if d.get("is_gateway")), None)
        if gateway and gateway["mac"] != "Desconhecido":
            known_gw_mac = self.network_meta.get("gateway_mac")
            if known_gw_mac is None:
                self.network_meta["gateway_mac"] = gateway["mac"]
                self._save_network_meta()
            elif known_gw_mac != gateway["mac"]:
                alerts.append(
                    f"O endereço MAC do roteador mudou de {known_gw_mac} para {gateway['mac']}. "
                    "Pode ser o roteador reiniciado/trocado — ou um sinal de ARP spoofing "
                    "(alguém se passando pelo roteador na rede)."
                )
                suspect_macs.add(gateway["mac"])
                self.network_meta["gateway_mac"] = gateway["mac"]
                self._save_network_meta()

        mac_to_ips = {}
        for d in devices:
            if d["mac"] == "Desconhecido":
                continue
            mac_to_ips.setdefault(d["mac"], []).append(d["ip"])
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                alerts.append(
                    f"O endereço MAC {mac} apareceu em {len(ips)} IPs ao mesmo tempo "
                    f"({', '.join(ips)}). Pode ser um dispositivo com múltiplas interfaces, "
                    "mas também é um sinal clássico de spoofing de ARP."
                )
                suspect_macs.add(mac)

        return alerts, suspect_macs

    def _notify_security_alerts(self, alerts):
        try:
            winsound.Beep(700, 150)
            winsound.Beep(700, 150)
        except RuntimeError:
            pass
        popup = tk.Toplevel(self.root)
        popup.overrideredirect(True)
        popup.attributes("-topmost", True)
        popup.configure(background=STATUS_CRITICAL)
        frame = tk.Frame(popup, background=SURFACE)
        frame.pack(fill="both", expand=True, padx=1, pady=1)
        inner = tk.Frame(frame, background=SURFACE, padx=10, pady=8)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text="⚠ Alerta de segurança", background=SURFACE,
                 foreground=STATUS_CRITICAL, font=("Segoe UI", 10, "bold"), anchor="w").pack(fill="x")
        for msg in alerts:
            tk.Label(inner, text=f"• {msg}", background=SURFACE, foreground=INK_SECONDARY,
                     font=("Segoe UI", 8), anchor="w", justify="left", wraplength=290).pack(fill="x", pady=(4, 0))

        self.root.update_idletasks()
        inner.update_idletasks()
        width = 320
        height = frame.winfo_reqheight() + 2
        x = self.root.winfo_x() + self.root.winfo_width() - width - 20
        y = self.root.winfo_y() + 40
        popup.geometry(f"{width}x{height}+{x}+{y}")
        popup.after(12000, popup.destroy)

    # ---------- Aba Rede Wi-Fi ----------
    def _handle_wifi_status(self, status):
        self.wifi_status = status
        self._update_network_health()
        if not status:
            for var in self.wifi_tiles.values():
                var.set("Sem Wi-Fi")
            self.adapter_var.set("")
            self.signal_history.append(None)
            self.speed_history.append(None)
            self._draw_wifi_sparkline("signal")
            self._draw_wifi_sparkline("speed")
            return

        if status["ssid"] != self._last_ssid:
            self._last_ssid = status["ssid"]
            self._password_cache = None
            self.password_var.set("")
            self.password_entry.config(show="•")
            self.show_pw_btn.config(text="Mostrar")

        self.wifi_tiles["ssid"].set(status["ssid"])
        sec_level = status.get("security_level", "desconhecida")
        sec_text = status["security"]
        if sec_level in ("aberta", "quebrada", "fraca"):
            sec_text = f"⚠ {sec_text}"
        self.wifi_tiles["security"].set(sec_text)
        self.wifi_tiles["signal"].set(f"{status['signal_percent']}%")
        self.wifi_tiles["channel"].set(f"{status['channel']} ({status['band']})")
        self.wifi_tiles["speed"].set(f"↓{_fmt_mbps(status['rx_mbps'])} / ↑{_fmt_mbps(status['tx_mbps'])} Mbps")

        try:
            self.signal_history.append(float(status["signal_percent"]))
        except (TypeError, ValueError):
            self.signal_history.append(None)
        try:
            self.speed_history.append(float(status["rx_mbps"]))
        except (TypeError, ValueError):
            self.speed_history.append(None)
        self._draw_wifi_sparkline("signal")
        self._draw_wifi_sparkline("speed")

        self.wifi_tiles["bssid"].set(status.get("bssid") or "—")
        rssi = status.get("rssi")
        self.wifi_tiles["rssi"].set(f"{rssi} dBm" if rssi and rssi != "?" else "—")
        self.wifi_tiles["cipher"].set(status.get("cipher") or "—")
        self.wifi_tiles["radio_type"].set(status.get("radio_type") or "—")
        self.wifi_tiles["connection_mode"].set(status.get("connection_mode") or "—")

        adapter = status.get("adapter")
        adapter_mac = status.get("adapter_mac")
        if adapter:
            self.adapter_var.set(f"Adaptador: {adapter}" + (f" ({adapter_mac})" if adapter_mac else ""))

    def _ensure_password_fetched(self):
        if self._password_cache is None and self.wifi_status:
            self._password_cache = wifi_info.get_saved_password(self.wifi_status["ssid"]) or "(não encontrada neste computador)"
            self.password_var.set(self._password_cache)

    def _toggle_password(self):
        if self.password_entry.cget("show") == "":
            self.password_entry.config(show="•")
            self.show_pw_btn.config(text="Mostrar")
        else:
            self._ensure_password_fetched()
            self.password_entry.config(show="")
            self.show_pw_btn.config(text="Ocultar")

    def _copy_password(self):
        self._ensure_password_fetched()
        value = self._password_cache or ""
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status_var.set(
            f"Senha copiada — será apagada da área de transferência em {CLIPBOARD_CLEAR_SECONDS}s."
        )
        self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000,
                         lambda: self._clear_clipboard_if_unchanged(value))

    def _clear_clipboard_if_unchanged(self, expected_value):
        """Limpa a área de transferência só se ela ainda tiver a senha que
        copiamos — evita apagar por engano algo que o usuário tenha copiado
        depois (ex.: prática comum em gerenciadores de senha)."""
        try:
            current = self.root.clipboard_get()
        except tk.TclError:
            return
        if current == expected_value:
            self.root.clipboard_clear()

    def _handle_latency(self, value):
        self.latency_history.append(value)
        self._draw_latency_chart()
        self._update_connection_health()

    def _compute_connection_health(self):
        history = list(self.latency_history)[-HEALTH_WINDOW:]
        if len(history) < 5:
            return "Coletando amostras…", INK_MUTED, "Aguarde cerca de 1 minuto para o primeiro diagnóstico."

        total = len(history)
        losses = sum(1 for v in history if v is None)
        loss_pct = losses / total * 100
        values = [v for v in history if v is not None]
        avg = sum(values) / len(values) if values else None
        jitter = (max(values) - min(values)) if len(values) >= 2 else 0

        if avg is None or loss_pct > 15:
            verdict, color = "RUIM", STATUS_CRITICAL
        elif loss_pct > 3 or avg > LATENCY_CRITICAL_MS or jitter > 80:
            verdict, color = "INSTÁVEL", STATUS_WARNING
        elif avg > LATENCY_WARNING_MS:
            verdict, color = "OK, COM PICOS", STATUS_WARNING
        else:
            verdict, color = "BOA", STATUS_GOOD

        detail_parts = []
        detail_parts.append(f"Latência média: {avg:.0f} ms" if avg is not None else "Roteador não respondeu")
        if loss_pct > 0:
            detail_parts.append(f"Perda de pacotes: {loss_pct:.0f}%")
        if values:
            detail_parts.append(f"Variação (jitter): {jitter:.0f} ms")
        detail_parts.append(f"Últimos {total} pings (~{total * LATENCY_SAMPLE_SECONDS}s)")
        return verdict, color, "\n".join(detail_parts)

    def _update_connection_health(self):
        verdict, color, detail = self._compute_connection_health()
        self.health_verdict_var.set(verdict)
        self.health_verdict_label.configure(foreground=color)
        self.health_detail_var.set(detail)
        self._update_network_health()

    # ---------- Nota única de saúde da rede ----------
    def _compute_network_health(self):
        """Combina segurança do Wi-Fi, estabilidade da conexão, confiança dos
        dispositivos e exposição de portas arriscadas numa única nota de 0 a
        100 — um raio-x rápido da rede, em vez de espalhar o diagnóstico em
        vários painéis separados. Cada componente só entra na conta quando já
        há dado suficiente para calculá-lo; os pesos são renormalizados sobre
        o que estiver disponível."""
        components = []  # lista de (peso, nota 0-100)

        if self.wifi_status:
            sec_score = {"segura": 100, "fraca": 55, "aberta": 0, "quebrada": 0}.get(
                self.wifi_status.get("security_level"))
            if sec_score is not None:
                components.append((HEALTH_WEIGHT_SECURITY, sec_score))

        verdict, _color, _detail = self._compute_connection_health()
        stability_score = {"BOA": 100, "OK, COM PICOS": 70, "INSTÁVEL": 40, "RUIM": 10}.get(verdict)
        if stability_score is not None:
            components.append((HEALTH_WEIGHT_STABILITY, stability_score))

        if self.last_devices:
            total = len(self.last_devices)
            suspects = sum(1 for d in self.last_devices if d["mac"] in self.suspect_macs)
            trust_score = max(0, 100 - round(suspects / total * 100))
            components.append((HEALTH_WEIGHT_TRUST, trust_score))

            risky = sum(
                1 for d in self.last_devices if not d.get("is_local") and not d.get("is_gateway")
                for port, _label in (d.get("open_ports") or [])
                if port in RISKY_OPEN_PORTS
            )
            port_score = max(0, 100 - risky * 20)
            components.append((HEALTH_WEIGHT_PORTS, port_score))

        if not components:
            return None, "Coletando dados…", INK_MUTED

        weight_sum = sum(weight for weight, _ in components)
        score = round(sum(weight * value for weight, value in components) / weight_sum)

        if score >= 80:
            label, color = "Boa", STATUS_GOOD
        elif score >= 55:
            label, color = "Atenção", STATUS_WARNING
        else:
            label, color = "Crítica", STATUS_CRITICAL
        return score, label, color

    def _update_network_health(self):
        score, label, color = self._compute_network_health()

        trend = ""
        if score is not None and self._health_score_prev is not None and score != self._health_score_prev:
            delta = score - self._health_score_prev
            trend = f"  {'▲' if delta > 0 else '▼'}{abs(delta)}"
        if score is not None:
            self._health_score_prev = score

        self.health_score_var.set(f"{label}{trend}" if score is not None else label)
        self.health_score_label.configure(foreground=color)

        self._health_gauge_target = score
        self._health_gauge_color = color if score is not None else INK_MUTED

    def _gauge_tick(self):
        """Anima o preenchimento do gauge de saúde da rede suavemente em
        direção à nota mais recente, em vez de pular direto para o novo
        valor — o mesmo tipo de microinteração que os medidores de atividade
        costumam usar."""
        target = self._health_gauge_target if self._health_gauge_target is not None else 0
        self._health_gauge_current += (target - self._health_gauge_current) * GAUGE_EASE
        if abs(target - self._health_gauge_current) < 0.3:
            self._health_gauge_current = target
        self._draw_health_gauge()
        self.root.after(GAUGE_TICK_MS, self._gauge_tick)

    def _draw_health_gauge(self):
        canvas = getattr(self, "health_gauge_canvas", None)
        if canvas is None:
            return
        canvas.delete("all")
        pad = GAUGE_THICKNESS / 2 + 1
        x0, y0, x1, y1 = pad, pad, GAUGE_SIZE - pad, GAUGE_SIZE - pad
        canvas.create_oval(x0, y0, x1, y1, outline=GRIDLINE, width=GAUGE_THICKNESS)
        if self._health_gauge_target is not None:
            extent = _score_to_arc_extent(self._health_gauge_current)
            if extent:
                canvas.create_arc(x0, y0, x1, y1, start=90, extent=extent,
                                   style="arc", outline=self._health_gauge_color, width=GAUGE_THICKNESS)
            text = str(round(self._health_gauge_current))
        else:
            text = "—"
        canvas.create_text(GAUGE_SIZE / 2, GAUGE_SIZE / 2, text=text, fill=INK_PRIMARY,
                            font=("Segoe UI", 11, "bold"))

    def _draw_latency_chart(self):
        canvas = self.latency_canvas
        canvas.delete("all")
        width = canvas.winfo_width() or 600
        height = canvas.winfo_height() or 200
        pad_left, pad_right, pad_top, pad_bottom = 42, 16, 16, 24

        history = list(self.latency_history)
        if len(history) < 2:
            canvas.create_text(width / 2, height / 2, text="Coletando amostras de latência…",
                                fill=INK_MUTED, font=("Segoe UI", 10))
            self._latency_points = []
            return

        plot_w = width - pad_left - pad_right
        plot_h = height - pad_top - pad_bottom
        values = [v for v in history if v is not None]
        raw_max = max(values) if values else 40
        max_val = max(20, math.ceil((raw_max + 5) / 10) * 10)

        steps = 4
        for i in range(steps + 1):
            y = pad_top + plot_h * i / steps
            val = max_val * (steps - i) / steps
            canvas.create_line(pad_left, y, width - pad_right, y, fill=GRIDLINE)
            canvas.create_text(pad_left - 6, y, text=f"{val:.0f}", fill=INK_MUTED,
                                font=("Segoe UI", 7), anchor="e")

        canvas.create_line(pad_left, pad_top, pad_left, height - pad_bottom, fill=BASELINE)
        canvas.create_line(pad_left, height - pad_bottom, width - pad_right, height - pad_bottom, fill=BASELINE)

        # linhas de referência dos limiares de alerta/crítico, quando visíveis na escala atual
        for threshold, color, label in ((LATENCY_CRITICAL_MS, STATUS_CRITICAL, "crítico"),
                                         (LATENCY_WARNING_MS, STATUS_WARNING, "alerta")):
            if threshold < max_val:
                y = pad_top + plot_h * (1 - threshold / max_val)
                canvas.create_line(pad_left, y, width - pad_right, y, fill=color, dash=(3, 3))
                canvas.create_text(width - pad_right - 4, y - 8, text=f"{label} {threshold}ms",
                                    fill=color, font=("Segoe UI", 7), anchor="e")

        n = len(history)
        step_x = plot_w / max(n - 1, 1)
        line_points = []
        self._latency_points = []
        for i, val in enumerate(history):
            x = pad_left + step_x * i
            if val is None:
                self._latency_points.append((x, None, None))
                continue
            y = pad_top + plot_h * (1 - min(val, max_val) / max_val)
            line_points.append((x, y))
            self._latency_points.append((x, y, val))

        if len(line_points) >= 2:
            flat = [coord for point in line_points for coord in point]
            canvas.create_line(*flat, fill=CAT_COMPUTADOR, width=2, capstyle="round", joinstyle="round")

        for x, y, val in self._latency_points:
            if val is None:
                canvas.create_oval(x - 4, height - pad_bottom - 4, x + 4, height - pad_bottom + 4,
                                    fill=STATUS_CRITICAL, outline="")
            elif val >= LATENCY_CRITICAL_MS:
                canvas.create_oval(x - 3.5, y - 3.5, x + 3.5, y + 3.5, fill=STATUS_CRITICAL, outline="")
            elif val >= LATENCY_WARNING_MS:
                canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill=STATUS_WARNING, outline="")

        latest = next((v for v in reversed(history) if v is not None), None)
        if latest is not None:
            latest_color = (STATUS_CRITICAL if latest >= LATENCY_CRITICAL_MS
                             else STATUS_WARNING if latest >= LATENCY_WARNING_MS else INK_PRIMARY)
            canvas.create_text(width - pad_right, pad_top - 8, anchor="ne",
                                text=f"{latest:.0f} ms", fill=latest_color, font=("Segoe UI", 10, "bold"))

    def _on_latency_hover(self, event):
        if len(self._latency_points) < 2:
            return
        nearest = min(self._latency_points, key=lambda p: abs(p[0] - event.x))
        self._draw_latency_chart()
        x, _y, val = nearest
        canvas = self.latency_canvas
        height = canvas.winfo_height()
        width = canvas.winfo_width()
        canvas.create_line(x, 0, x, height, fill=BASELINE, dash=(2, 2))
        label = f"{val:.0f} ms" if val is not None else "perda de pacote"
        box_w = 74
        bx = min(max(x - box_w / 2, 4), width - box_w - 4)
        canvas.create_rectangle(bx, 4, bx + box_w, 22, fill="#000000", outline=BASELINE)
        canvas.create_text(bx + box_w / 2, 13, text=label, fill=INK_PRIMARY, font=("Segoe UI", 8, "bold"))

    # ---------- Mapa de topologia ----------
    def _draw_map(self, devices):
        canvas = self.map_canvas
        canvas.delete("all")
        self.map_nodes = []
        width = canvas.winfo_width() or 800
        height = canvas.winfo_height() or 400
        cx, cy = width / 2, height / 2 + 6

        if not devices:
            canvas.create_text(cx, cy, text="Sem dados ainda — clique em \"Escanear agora\"",
                                fill=INK_MUTED, font=("Segoe UI", 11))
            return

        gateway = next((d for d in devices if d.get("is_gateway")), None)
        others = [d for d in devices if d is not gateway]

        node_r = 30
        min_arc_per_node = 130  # espaço mínimo (px) por nó+rótulo ao redor do anel
        max_radius = max(90, min(width, height) / 2 - 130)
        ring_capacity = max(6, int((2 * math.pi * max_radius) // min_arc_per_node))
        ideal_radius = max(90, min(max_radius, len(others) * min_arc_per_node / (2 * math.pi)))
        positions = self._ring_positions(len(others), cx, cy, ideal_radius, ring_capacity=ring_capacity)

        for (x, y), _d in zip(positions, others):
            canvas.create_line(cx, cy, x, y, fill=GRIDLINE, width=1.5)

        for (x, y), d in zip(positions, others):
            kind = d.get("kind", "outro")
            color = DEVICE_COLORS.get(kind, CAT_OUTRO)
            if d.get("is_local"):
                canvas.create_oval(x - node_r - 4, y - node_r - 4, x + node_r + 4, y + node_r + 4,
                                    outline=INK_PRIMARY, width=2)
            canvas.create_oval(x - node_r, y - node_r, x + node_r, y + node_r,
                                fill=color, outline=SURFACE, width=2)
            DEVICE_ICON_DRAWERS.get(kind, _icon_outro)(canvas, x, y, node_r, "white")

            if d["hostname"] != "Desconhecido":
                name = d["hostname"]
                if len(name) > 16:
                    name = name[:14] + "…"
                canvas.create_text(x, y - node_r - 12, text=name, fill=INK_PRIMARY, font=("Segoe UI", 8, "bold"))
                canvas.create_text(x, y + node_r + 10, text=d["ip"], fill=INK_SECONDARY, font=("Segoe UI", 7))
            else:
                canvas.create_text(x, y - node_r - 12, text=d["ip"], fill=INK_PRIMARY, font=("Segoe UI", 8, "bold"))

            self.map_nodes.append((x, y, node_r, d))

        hub_label = gateway["hostname"] if gateway and gateway["hostname"] != "Desconhecido" else "Roteador"
        hub_ip = gateway["ip"] if gateway else "não identificado"
        canvas.create_oval(cx - 42, cy - 42, cx + 42, cy + 42,
                            fill=CAT_ROTEADOR, outline=SURFACE, width=3)
        canvas.create_text(cx, cy - 8, text=hub_label, fill="white", font=("Segoe UI", 9, "bold"), justify="center")
        canvas.create_text(cx, cy + 10, text=hub_ip, fill="#ffe3d0", font=("Segoe UI", 7), justify="center")
        if gateway:
            self.map_nodes.append((cx, cy, 42, gateway))

    def _ring_positions(self, n, cx, cy, base_radius, ring_capacity=12, ring_gap=95):
        positions = []
        remaining = n
        ring = 0
        base_step = 2 * math.pi / ring_capacity
        while remaining > 0:
            capacity = ring_capacity + ring * 5
            count = min(capacity, remaining)
            radius = base_radius + ring * ring_gap
            # anéis ímpares começam meio passo adiante, evitando que os nós
            # (e seus rótulos) fiquem alinhados radialmente com o anel anterior
            offset = (base_step / 2) if ring % 2 == 1 else 0
            for i in range(count):
                angle = (2 * math.pi * i / count) - math.pi / 2 + offset
                positions.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
            remaining -= count
            ring += 1
        return positions


    def _on_map_hover(self, event):
        hit = None
        for x, y, r, d in self.map_nodes:
            if (event.x - x) ** 2 + (event.y - y) ** 2 <= r ** 2:
                hit = d
                break
        key = hit["ip"] if hit else None
        if key == self._map_tooltip_ip:
            return
        self._map_tooltip_ip = key
        self.map_canvas.delete("tooltip")
        if not hit:
            return

        text = self._format_device_details(hit)
        canvas = self.map_canvas
        tx, ty = event.x + 16, event.y + 12
        item = canvas.create_text(tx, ty, text=text, fill="white", font=("Segoe UI", 8),
                                   anchor="nw", tags="tooltip", justify="left", width=320)
        bbox = canvas.bbox(item)
        if bbox:
            rect = canvas.create_rectangle(bbox[0] - 6, bbox[1] - 4, bbox[2] + 6, bbox[3] + 4,
                                            fill="#000000", outline=BASELINE, tags="tooltip")
            canvas.tag_raise(item, rect)

    def _clear_map_tooltip(self):
        self._map_tooltip_ip = None
        self.map_canvas.delete("tooltip")

    # ---------- Radar Wi-Fi (redes vizinhas) ----------
    def _radar_tick(self):
        self._radar_angle = (self._radar_angle + RADAR_SWEEP_DEG_PER_TICK) % 360
        self._draw_radar()
        self.root.after(RADAR_TICK_MS, self._radar_tick)

    def _draw_radar(self):
        canvas = getattr(self, "radar_canvas", None)
        if canvas is None:
            return
        canvas.delete("all")
        self._radar_nodes = []
        width = canvas.winfo_width() or 700
        height = canvas.winfo_height() or 500
        cx, cy = width / 2, height / 2
        max_radius = max(80, min(width, height) / 2 - 40)
        min_radius = 28

        for frac in (0.25, 0.5, 0.75, 1.0):
            r = max_radius * frac
            canvas.create_oval(cx - r, cy - r, cx + r, cy + r, outline=RADAR_RING, width=1)
        canvas.create_line(cx - max_radius, cy, cx + max_radius, cy, fill=RADAR_RING)
        canvas.create_line(cx, cy - max_radius, cx, cy + max_radius, fill=RADAR_RING)

        angle_rad = math.radians(self._radar_angle)
        canvas.create_arc(
            cx - max_radius, cy - max_radius, cx + max_radius, cy + max_radius,
            start=-self._radar_angle - 30, extent=30,
            fill=RADAR_RING, outline="", stipple="gray25",
        )
        sx = cx + max_radius * math.cos(angle_rad)
        sy = cy + max_radius * math.sin(angle_rad)
        canvas.create_line(cx, cy, sx, sy, fill=RADAR_GREEN_BRIGHT, width=2)

        own_ssid = self.wifi_status["ssid"] if self.wifi_status else None

        for net in self.nearby_networks:
            seed = int(hashlib.md5(net["bssid"].encode()).hexdigest(), 16)
            angle = math.radians(seed % 360)
            signal = net.get("signal_percent", 0)
            radius = min_radius + (max_radius - min_radius) * (1 - signal / 100)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)

            is_own = net["ssid"] == own_ssid
            level = net.get("security_level", "desconhecida")
            if is_own:
                color = RADAR_ACCENT
            elif level in ("aberta", "quebrada"):
                color = STATUS_CRITICAL
            elif level == "fraca":
                color = STATUS_WARNING
            else:
                color = RADAR_GREEN
            blip_r = 7 if is_own else 5
            canvas.create_oval(x - blip_r - 3, y - blip_r - 3, x + blip_r + 3, y + blip_r + 3,
                                outline=color, width=1)
            canvas.create_oval(x - blip_r, y - blip_r, x + blip_r, y + blip_r, fill=color, outline="")
            if is_own or level in ("aberta", "quebrada"):
                label = net["ssid"]
                if len(label) > 18:
                    label = label[:16] + "…"
                canvas.create_text(x, y - blip_r - 10, text=label, fill=color, font=("Consolas", 8, "bold"))

            self._radar_nodes.append((x, y, blip_r + 6, net))

        canvas.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill=RADAR_GREEN_BRIGHT, outline="")

        if not self.nearby_networks:
            canvas.create_text(cx, cy + max_radius * 0.4, text="Procurando redes próximas…",
                                fill=RADAR_RING, font=("Segoe UI", 10))

        if self._radar_tooltip_bssid:
            net = next((n for n in self.nearby_networks if n["bssid"] == self._radar_tooltip_bssid), None)
            if net:
                self._draw_radar_tooltip(net, *self._radar_last_xy)
            else:
                self._radar_tooltip_bssid = None

    def _draw_radar_tooltip(self, net, x, y):
        canvas = self.radar_canvas
        text = self._format_network_details(net)
        tx, ty = x + 16, y + 12
        item = canvas.create_text(tx, ty, text=text, fill=RADAR_TEXT, font=("Consolas", 8),
                                   anchor="nw", justify="left")
        bbox = canvas.bbox(item)
        if bbox:
            rect = canvas.create_rectangle(bbox[0] - 6, bbox[1] - 4, bbox[2] + 6, bbox[3] + 4,
                                            fill="#04140a", outline=RADAR_RING)
            canvas.tag_raise(item, rect)

    def _on_radar_hover(self, event):
        hit = None
        for x, y, r, net in self._radar_nodes:
            if (event.x - x) ** 2 + (event.y - y) ** 2 <= r ** 2:
                hit = net
                break
        self._radar_tooltip_bssid = hit["bssid"] if hit else None
        self._radar_last_xy = (event.x, event.y)

    def _on_radar_leave(self, _event):
        self._radar_tooltip_bssid = None

    def _refresh_nearby_tree(self, networks):
        tree = getattr(self, "nearby_tree", None)
        if tree is None:
            return
        self.nearby_count_var.set(f"REDES ENCONTRADAS ({len(networks)})")
        selected = tree.selection()
        selected_bssid = selected[0] if selected else None
        tree.delete(*tree.get_children())
        own_ssid = self.wifi_status["ssid"] if self.wifi_status else None
        for net in sorted(networks, key=lambda n: -n["signal_percent"]):
            level = net.get("security_level", "desconhecida")
            if net["ssid"] == own_ssid:
                tags = ("own",)
            elif level in ("aberta", "quebrada"):
                tags = ("insecure_critical",)
            elif level == "fraca":
                tags = ("insecure_weak",)
            else:
                tags = ()
            security_display = net["security"]
            if level in ("aberta", "quebrada", "fraca"):
                security_display = f"⚠ {security_display}"
            tree.insert("", "end", iid=net["bssid"], values=(
                net["ssid"], f"{net['signal_percent']}%", net["channel"], security_display,
            ), tags=tags)
        if selected_bssid and tree.exists(selected_bssid):
            tree.selection_set(selected_bssid)

    def _on_nearby_tree_select(self, _event):
        selection = self.nearby_tree.selection()
        if not selection:
            return
        bssid = selection[0]
        net = next((n for n in self.nearby_networks if n["bssid"] == bssid), None)
        if not net:
            return
        self.nearby_detail_var.set(self._format_network_details(net))

    def _format_network_details(self, net):
        stations = net.get("connected_stations")
        utilization = net.get("channel_utilization_pct")
        level = net.get("security_level", "desconhecida")
        label = net.get("security_label", net["security"])
        alert_prefix = "⚠ " if level in ("aberta", "quebrada", "fraca") else ""
        return "\n".join([
            f"SSID: {net['ssid']}",
            f"BSSID: {net['bssid']}",
            f"Sinal: {net['signal_percent']}%",
            f"Canal: {net['channel']}   Banda: {net['band']}",
            f"Segurança: {net['security']}",
            f"Nível de proteção: {alert_prefix}{label}",
            f"Criptografia: {net.get('cipher', '?')}",
            f"Padrão Wi-Fi: {net.get('radio_type', '?')}",
            f"Tipo de rede: {net.get('network_type', '?')}",
            f"Estações conectadas: {stations if stations is not None else '?'}",
            f"Uso do canal: {utilization}%" if utilization is not None else "Uso do canal: ?",
        ])

    # ---------- Notificações ----------
    def _notify_new_devices(self, new_devices):
        try:
            winsound.Beep(1200, 200)
        except RuntimeError:
            pass
        popup = tk.Toplevel(self.root)
        popup.overrideredirect(True)
        popup.attributes("-topmost", True)
        popup.configure(background=ACCENT)
        self.root.update_idletasks()
        x = self.root.winfo_x() + self.root.winfo_width() - 320
        y = self.root.winfo_y() + 40
        popup.geometry(f"300x{54 + 20 * len(new_devices)}+{x}+{y}")
        frame = tk.Frame(popup, background=SURFACE)
        frame.pack(fill="both", expand=True, padx=1, pady=1)
        inner = tk.Frame(frame, background=SURFACE, padx=10, pady=8)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text="Novo(s) dispositivo(s) detectado(s):", background=SURFACE,
                 foreground=INK_PRIMARY, font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x")
        for d in new_devices:
            tk.Label(inner, text=f"• {d['hostname']} — {d['ip']}", background=SURFACE,
                     foreground=INK_SECONDARY, font=("Segoe UI", 9), anchor="w").pack(fill="x")
        popup.after(6000, popup.destroy)

    def _on_close(self):
        self.monitoring = False
        self._save_known_devices()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        root.iconbitmap(_resource_path("icon.ico"))
    except tk.TclError:
        pass
    _configure_style()
    root.configure(background=BG_APP)
    NetworkMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
