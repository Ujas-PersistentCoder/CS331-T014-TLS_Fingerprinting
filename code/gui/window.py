from pathlib import Path
import shutil
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTableWidget, QTableWidgetItem, QFileDialog, QHeaderView, 
    QComboBox, QLabel, QTextEdit, QInputDialog, QAbstractItemView
)
from scapy.all import get_working_ifaces, wrpcap
from src.db import FingerprintDB
from workers import PcapWorker, LiveCaptureWorker

class TlsMonitorGui(QMainWindow):
    def __init__(self, pythonEngineDir):
        super().__init__()
        self.setWindowTitle("TLS Fingerprint Monitor")
        self.resize(1150, 650)
        self.dbPath = pythonEngineDir / "fingerprints.json"
        self.pcapsDir = pythonEngineDir.parent / "pcaps"
        self.fingerprintDb = FingerprintDB(str(self.dbPath))
        self.pcapWorker = None
        self.liveWorker = None
        self.rowCache = []
        self.capturedPackets = []
        self.loadedPcapPath = None

        mainWidget = QWidget()
        self.setCentralWidget(mainWidget)
        mainLayout = QVBoxLayout(mainWidget)

        controlLayout = QHBoxLayout()

        self.loadButton = QPushButton("Load PCAP File")
        self.loadButton.clicked.connect(self.selectPcapFile)
        controlLayout.addWidget(self.loadButton)

        self.saveButton = QPushButton("Save PCAP")
        self.saveButton.clicked.connect(self.savePcapFile)
        controlLayout.addWidget(self.saveButton)

        self.clearButton = QPushButton("Clear Records")
        self.clearButton.clicked.connect(self.clearRecords)
        controlLayout.addWidget(self.clearButton)

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

        self.labelButton = QPushButton("Label Selected Fingerprint")
        self.labelButton.clicked.connect(self.labelSelectedFingerprint)
        self.labelButton.setEnabled(False)
        controlLayout.addWidget(self.labelButton)

        controlLayout.addStretch()
        mainLayout.addLayout(controlLayout)

        self.dataTable = QTableWidget(0, 7)
        self.dataTable.setHorizontalHeaderLabels([
            "Source", "Destination", "SNI", "JA3 Hash", "JA4 Hash",
            "JA3 Match", "JA4 Match"
        ])
        self.dataTable.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.dataTable.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.dataTable.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
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
            self.capturedPackets.clear()
            self.loadedPcapPath = filePath
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
            self.capturedPackets.clear()
            self.loadedPcapPath = None
            self.detailsPane.clear()

            self.liveWorker = LiveCaptureWorker(
                selectedInterface, self.dbPath, packetBuffer=self.capturedPackets
            )
            self.liveWorker.rowExtracted.connect(self.appendTableRow)
            self.liveWorker.errorOccurred.connect(
                lambda errorMsg: self.detailsPane.setText(errorMsg)
            )
            self.liveWorker.start()
            self.liveButton.setText("Stop Live Capture")
            self.loadButton.setEnabled(False)

    def clearRecords(self):
        self.dataTable.setRowCount(0)
        self.rowCache.clear()
        self.capturedPackets.clear()
        self.loadedPcapPath = None
        self.detailsPane.clear()
        self.labelButton.setEnabled(False)

    def savePcapFile(self):
        if not self.capturedPackets and not self.loadedPcapPath:
            self.detailsPane.setText("No captured or loaded packets available to save.")
            return

        savePath, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", str(self.pcapsDir / "captured.pcap"), "PCAP Files (*.pcap *.pcapng)"
        )
        if not savePath:
            return

        try:
            if self.capturedPackets:
                packetsSnapshot = list(self.capturedPackets)
                wrpcap(savePath, packetsSnapshot)
                self.detailsPane.setText(f"Successfully saved {len(packetsSnapshot)} packet(s) to {savePath}")
            elif self.loadedPcapPath:
                shutil.copyfile(self.loadedPcapPath, savePath)
                self.detailsPane.setText(f"Successfully exported PCAP to {savePath}")
        except Exception as err:
            self.detailsPane.setText(f"Failed to save PCAP: {err}")

    def appendTableRow(self, packetData):
        currentRow = self.dataTable.rowCount()
        self.dataTable.insertRow(currentRow)
        self.rowCache.append(packetData)

        columnValues = [
            packetData["source"],
            packetData["destination"],
            packetData["sni"],
            packetData["ja3Hash"],
            packetData["ja4Hash"],
            packetData["ja3Match"],
            packetData["ja4Match"],
        ]

        for colIdx, val in enumerate(columnValues):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.dataTable.setItem(currentRow, colIdx, item)

    def displayRowDetails(self):
        selectedRows = self.dataTable.selectionModel().selectedRows()
        if not selectedRows:
            self.labelButton.setEnabled(False)
            return

        rowIndex = selectedRows[0].row()
        if rowIndex < len(self.rowCache):
            entry = self.rowCache[rowIndex]
            isUnknown = entry.get("ja3Match") == "Unknown" or entry.get("ja4Match") == "Unknown"
            self.labelButton.setEnabled(isUnknown)
            detailText = (
                f"SNI:        {entry['sni']}\n"
                f"JA3 Hash:   {entry['ja3Hash']}\n"
                f"JA3 Match:  {entry['ja3Match']}\n"
                f"JA4 Hash:   {entry['ja4Hash']}\n"
                f"JA4 Match:  {entry['ja4Match']}\n"
                f"Raw JA3:    {entry.get('ja3Raw', 'N/A')}"
            )
            self.detailsPane.setText(detailText)

    def labelSelectedFingerprint(self):
        selectedRows = self.dataTable.selectionModel().selectedRows()
        if not selectedRows:
            return

        rowIndex = selectedRows[0].row()
        if rowIndex >= len(self.rowCache):
            return

        entry = self.rowCache[rowIndex]
        if entry.get("ja3Match") != "Unknown" and entry.get("ja4Match") != "Unknown":
            return

        label, accepted = QInputDialog.getText(
            self,
            "Label Fingerprint",
            "Verified client name:",
        )
        if not accepted or not label.strip():
            return

        try:
            pair = (
                ("ja3", "ja3Hash", "ja3Match", 3),
                ("ja4", "ja4Hash", "ja4Match", 4),
            )
            if entry.get("fingerprintKind") == "ja3s":
                pair = (
                    ("ja3s", "ja3Hash", "ja3Match", 3),
                    ("ja4s", "ja4Hash", "ja4Match", 4),
                )
            for kind, hash_key, match_key, _ in pair:
                if entry.get(match_key) == "Unknown":
                    self.fingerprintDb.enroll(entry[hash_key], kind, label)
        except (OSError, ValueError) as error:
            self.detailsPane.setText(f"Could not save fingerprint: {error}")
            return

        for match_key, target_column in (("ja3Match", 5), ("ja4Match", 6)):
            if entry.get(match_key) == "Unknown":
                entry[match_key] = label.strip()
                newItem = QTableWidgetItem(entry[match_key])
                newItem.setFlags(newItem.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.dataTable.setItem(rowIndex, target_column, newItem)
        self.displayRowDetails()