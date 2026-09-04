from pathlib import Path
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTableWidget, QTableWidgetItem, QFileDialog, QHeaderView, 
    QComboBox, QLabel, QTextEdit
)
from scapy.all import get_working_ifaces
from workers import PcapWorker, LiveCaptureWorker

class TlsMonitorGui(QMainWindow):
    def __init__(self, pythonEngineDir):
        super().__init__()
        self.setWindowTitle("TLS Fingerprint Monitor")
        self.resize(1100, 650)

        self.dbPath = pythonEngineDir / "fingerprints.json"
        self.pcapsDir = pythonEngineDir.parent / "pcaps"
        self.pcapWorker = None
        self.liveWorker = None
        self.rowCache = []

        mainWidget = QWidget()
        self.setCentralWidget(mainWidget)
        mainLayout = QVBoxLayout(mainWidget)

        controlLayout = QHBoxLayout()

        self.loadButton = QPushButton("Load PCAP File")
        self.loadButton.clicked.connect(self.selectPcapFile)
        controlLayout.addWidget(self.loadButton)

        controlLayout.addWidget(QLabel("Interface:"))
        self.interfaceDropdown = QComboBox()
        try:
            for iface in get_working_ifaces():
                self.interfaceDropdown.addItem(iface.name, iface.network_name)
        except Exception:
            self.interfaceDropdown.addItem("Default", "Default")
        controlLayout.addWidget(self.interfaceDropdown)

        self.liveButton = QPushButton("Start Live Capture")
        self.liveButton.clicked.connect(self.toggleLiveCapture)
        controlLayout.addWidget(self.liveButton)

        controlLayout.addStretch()
        mainLayout.addLayout(controlLayout)

        self.dataTable = QTableWidget(0, 5)
        self.dataTable.setHorizontalHeaderLabels([
            "Source", "Destination", "SNI", "JA3 Hash", "Matched Client"
        ])
        self.dataTable.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.dataTable.itemSelectionChanged.connect(self.displayRowDetails)
        mainLayout.addWidget(self.dataTable)

        self.detailsPane = QTextEdit()
        self.detailsPane.setReadOnly(True)
        self.detailsPane.setFixedHeight(120)
        self.detailsPane.setPlaceholderText("Select any handshake above to view raw metadata and JA3 string.")
        mainLayout.addWidget(self.detailsPane)

    def selectPcapFile(self):
        filePath, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP", str(self.pcapsDir), "PCAP Files (*.pcap *.pcapng)"
        )
        if filePath:
            self.dataTable.setRowCount(0)
            self.rowCache.clear()
            self.detailsPane.clear()

            self.pcapWorker = PcapWorker(filePath, self.dbPath)
            self.pcapWorker.rowExtracted.connect(self.appendTableRow)
            self.pcapWorker.errorOccurred.connect(lambda err: self.detailsPane.setText(f"Error: {err}"))
            self.pcapWorker.start()

    def toggleLiveCapture(self):
        if self.liveWorker and self.liveWorker.isRunning:
            self.liveWorker.stopCapture()
            self.liveWorker = None
            self.liveButton.setText("Start Live Capture")
            self.loadButton.setEnabled(True)
        else:
            selectedInterface = self.interfaceDropdown.currentData()
            self.dataTable.setRowCount(0)
            self.rowCache.clear()
            self.detailsPane.clear()

            self.liveWorker = LiveCaptureWorker(selectedInterface, self.dbPath)
            self.liveWorker.rowExtracted.connect(self.appendTableRow)
            
            # Bind the new error signal to the UI pane
            self.liveWorker.errorOccurred.connect(
                lambda errorMsg: self.detailsPane.setText(errorMsg)
            )

            self.liveWorker.start()
            self.liveButton.setText("Stop Live Capture")
            self.loadButton.setEnabled(False)

    def appendTableRow(self, packetData):
        currentRow = self.dataTable.rowCount()
        self.dataTable.insertRow(currentRow)
        self.rowCache.append(packetData)

        self.dataTable.setItem(currentRow, 0, QTableWidgetItem(packetData["source"]))
        self.dataTable.setItem(currentRow, 1, QTableWidgetItem(packetData["destination"]))
        self.dataTable.setItem(currentRow, 2, QTableWidgetItem(packetData["sni"]))
        self.dataTable.setItem(currentRow, 3, QTableWidgetItem(packetData["ja3Hash"]))
        self.dataTable.setItem(currentRow, 4, QTableWidgetItem(packetData["matchedClient"]))

    def displayRowDetails(self):
        selectedRows = self.dataTable.selectionModel().selectedRows()
        if not selectedRows:
            return
        rowIndex = selectedRows[0].row()
        if rowIndex < len(self.rowCache):
            entry = self.rowCache[rowIndex]
            detailText = (
                f"SNI:        {entry['sni']}\n"
                f"JA3 Hash:   {entry['ja3Hash']}\n"
                f"Client:     {entry['matchedClient']}\n"
                f"Raw JA3:    {entry.get('ja3Raw', 'N/A')}"
            )
            self.detailsPane.setText(detailText)