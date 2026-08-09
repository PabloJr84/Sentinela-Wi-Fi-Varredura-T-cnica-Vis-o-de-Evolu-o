"""Log central do app. Antes, falhas em quase todo lugar eram engolidas com
`except Exception: pass` — funcionalmente seguro (a UI não trava), mas sem
nenhum rastro de diagnóstico quando algo dá errado no computador de um
usuário. Isso grava as falhas que realmente importam (não as rotineiras,
como um IP que simplesmente não respondeu ao ping) em
%APPDATA%/Sentinela Wi-Fi/log.txt, sem mudar o comportamento visível do app."""
import logging
import logging.handlers
import os

APP_NAME = "Sentinela Wi-Fi"
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)
LOG_FILE = os.path.join(DATA_DIR, "log.txt")

_logger = None
_logged_once_keys = set()


def log_once(logger, key, message, *, level=logging.WARNING, exc_info=False):
    """Loga `message` apenas na primeira vez que essa `key` aparece nesta
    execução do app. Usado nos laços de verificação periódica (a cada 10-20s)
    para não inundar o log com a mesma falha repetida indefinidamente —
    a primeira ocorrência já é suficiente para diagnosticar o problema."""
    if key in _logged_once_keys:
        return
    _logged_once_keys.add(key)
    logger.log(level, message, exc_info=exc_info)


def get_logger():
    """Retorna o logger central do app, criando-o (com rotação de arquivo) na
    primeira chamada. Se nem isso for possível (ex.: disco cheio, sem
    permissão), cai para um logger sem efeito — nunca deve derrubar o app."""
    global _logger
    if _logger is not None:
        return _logger

    logger = logging.getLogger("sentinela_wifi")
    logger.setLevel(logging.INFO)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=1_000_000, backupCount=2, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(handler)
    except OSError:
        logger.addHandler(logging.NullHandler())
    _logger = logger
    return logger
