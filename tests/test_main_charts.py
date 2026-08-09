"""Testes das funções puras de desenho de main.py (gauge de saúde da rede,
sparklines e ícones vetoriais dos dispositivos) — sem precisar abrir uma
janela do Tkinter. Importar main.py não cria nenhuma janela: a criação do
Tk() só acontece dentro de main(), atrás do `if __name__ == "__main__"`."""
import main


# ---------- Gauge de saúde da rede ----------

def test_score_to_arc_extent_zero():
    assert main._score_to_arc_extent(0) == 0


def test_score_to_arc_extent_full():
    assert main._score_to_arc_extent(100) == -360


def test_score_to_arc_extent_half():
    assert main._score_to_arc_extent(50) == -180


def test_score_to_arc_extent_none_is_zero():
    assert main._score_to_arc_extent(None) == 0


def test_score_to_arc_extent_clamps_out_of_range():
    assert main._score_to_arc_extent(150) == -360
    assert main._score_to_arc_extent(-10) == 0


# ---------- Sparklines ----------

def test_sparkline_points_empty_history_returns_nothing():
    assert main._sparkline_points([], 100, 20) == []


def test_sparkline_points_needs_at_least_two_values():
    assert main._sparkline_points([50], 100, 20) == []
    assert main._sparkline_points([None, 50], 100, 20) == []


def test_sparkline_points_count_matches_non_none_values():
    points = main._sparkline_points([10, None, 30, 40], 90, 20, y_max=100)
    assert len(points) == 3  # o None vira uma lacuna, não um ponto


def test_sparkline_points_higher_value_is_drawn_higher_on_screen():
    # No Canvas, y cresce para baixo — um valor maior deve gerar um y menor.
    points = main._sparkline_points([10, 90], 100, 40, y_max=100)
    (_x0, y_low_value), (_x1, y_high_value) = points
    assert y_high_value < y_low_value


def test_sparkline_points_respects_canvas_width():
    points = main._sparkline_points([1, 2, 3], 200, 20, y_max=10)
    xs = [x for x, _y in points]
    assert xs[0] == 0
    assert xs[-1] == 200


# ---------- Ícones vetoriais dos dispositivos ----------

class _RecordingCanvas:
    """Substitui um tk.Canvas real só para confirmar que cada função de
    ícone desenha algo (chama pelo menos um create_*), sem precisar de tela."""
    def __init__(self):
        self.calls = 0

    def __getattr__(self, _name):
        def _record(*_args, **_kwargs):
            self.calls += 1
            return self.calls
        return _record


def test_every_device_kind_has_an_icon_drawer():
    for kind in main.DEVICE_LABELS:
        assert kind in main.DEVICE_ICON_DRAWERS


def test_icon_drawers_draw_something_for_every_kind():
    for kind, draw in main.DEVICE_ICON_DRAWERS.items():
        canvas = _RecordingCanvas()
        draw(canvas, 50, 50, 30, "white")
        assert canvas.calls > 0, f"ícone de '{kind}' não desenhou nada"
