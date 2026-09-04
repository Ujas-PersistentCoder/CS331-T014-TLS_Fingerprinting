import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QHeaderView,
)
from PyQt6.QtCore import QThread, pyqtSignal

# Resolve path to code/python so we can import the capture and ja3 modules
currentDir = Path(__file__).resolve().parent
pythonEngineDir = currentDir.parent / "python"
if str(pythonEngineDir) not in sys.path:
    sys.path.insert(0, str(pythonEngineDir))

from src.capture import read_pcap, CaptureStats
from src.ja3 import compute_ja3_hash
from src.db import FingerprintDB


class PcapWorker(QThread):
    rowExtracted = pyqtSignal(dict)
    captureFinished = pyqtSignal(str)

    def __init__(self, pcapPath: str, dbPath: Path):
        super().__init__()
        self.pcapPath = pcapPath
        self.fingerprintDb = FingerprintDB(str(dbPath))
        self.captureStats = CaptureStats()

    def run(self):
        for result in read_pcap(self.pcapPath, self.captureStats):
            if result.client_hello:
                clientHello = result.client_hello
                ja3Hash = compute_ja3_hash(clientHello)
                match = self.fingerprintDb.lookup(ja3Hash) or "Unknown"

                packetData = {
                    "source": f"{result.src_ip}:{result.src_port}",
                    "destination": f"{result.dst_ip}:{result.dst_port}",
                    "sni": clientHello.server_name or "N/A",
                    "ja3Hash": ja3Hash,
                    "matchedClient": match,
                }
                self.rowExtracted.emit(packetData)

        self.captureFinished.emit(self.captureStats.summary())


class TlsMonitorGui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TLS Fingerprint Monitor")
        self.resize(1000, 600)

        self.dbPath = pythonEngineDir / "fingerprints.json"
        self.workerThread = None

        mainWidget = QWidget()
        self.setCentralWidget(mainWidget)
        mainLayout = QVBoxLayout(mainWidget)

        # Top Controls
        controlLayout = QHBoxLayout()
        self.loadButton = QPushButton("Load PCAP File")
        self.loadButton.clicked.connect(self.selectPcapFile)
        controlLayout.addWidget(self.loadButton)
        controlLayout.addStretch()
        mainLayout.addLayout(controlLayout)

        # Data Table
        self.dataTable = QTableWidget(0, 5)
        self.dataTable.setHorizontalHeaderLabels([
            "Source",
            "Destination",
            "SNI",
            "JA3 Hash",
            "Matched Client",
        ])
        self.dataTable.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        mainLayout.addWidget(self.dataTable)

    def selectPcapFile(self):
        defaultPcapDir = str(currentDir.parent / "pcaps")
        filePath, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP",
            defaultPcapDir,
            "PCAP Files (*.pcap *.pcapng)",
        )
        if filePath:
            self.dataTable.setRowCount(0)
            self.workerThread = PcapWorker(filePath, self.dbPath)
            self.workerThread.rowExtracted.connect(self.appendTableRow)
            self.workerThread.start()

    def appendTableRow(self, packetData):
        currentRow = self.dataTable.rowCount()
        self.dataTable.insertRow(currentRow)
        self.dataTable.setItem(currentRow, 0, QTableWidgetItem(packetData["source"]))
        self.dataTable.setItem(currentRow, 1, QTableWidgetItem(packetData["destination"]))
        self.dataTable.setItem(currentRow, 2, QTableWidgetItem(packetData["sni"]))
        self.dataTable.setItem(currentRow, 3, QTableWidgetItem(packetData["ja3Hash"]))
        self.dataTable.setItem(currentRow, 4, QTableWidgetItem(packetData["matchedClient"]))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    monitorWindow = TlsMonitorGui()
    monitorWindow.show()
    sys.exit(app.exec())