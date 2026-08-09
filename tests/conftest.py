import sys
from pathlib import Path

# Permite `import scanner` / `import wifi_info` a partir de tests/ sem
# precisar instalar o projeto como pacote.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
