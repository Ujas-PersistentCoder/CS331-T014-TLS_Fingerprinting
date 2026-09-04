import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication

# Resolve paths before importing window
currentDir = Path(__file__).resolve().parent
pythonEngineDir = currentDir.parent / "python"
if str(pythonEngineDir) not in sys.path:
    sys.path.insert(0, str(pythonEngineDir))

from window import TlsMonitorGui

if __name__ == "__main__":
    app = QApplication(sys.argv)
    monitorWindow = TlsMonitorGui(pythonEngineDir)
    monitorWindow.show()
    sys.exit(app.exec())