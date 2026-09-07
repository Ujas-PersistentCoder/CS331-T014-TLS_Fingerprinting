from pathlib import Path
import shutil
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QFileDialog, QHeaderView,
    QComboBox, QLabel, QTextEdit, QInputDialog, QAbstractItemView,
    QLineEdit
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
        self.fingerprintDb = None 
        self.pcapWorker = None
        self.liveWorker = None
        self.rowCache = []
        self.capturedPackets = []
        self.loadedPcapPath = None
        mainWidget = QWidget()
        self.setCentralWidget(mainWidget)
        mainLayout = QVBoxLayout(mainWidget)
        controlLayout = QHBoxLayout()
        self.loadButton = QPushButton("Load PCAP")
        self.loadButton.clicked.connect(self.selectPcapFile)
        controlLayout.addWidget(self.loadButton)
        self.cancelLoadButton = QPushButton("Cancel Load")
        self.cancelLoadButton.clicked.connect(self.cancelPcapLoad)
        self.cancelLoadButton.setEnabled(False)
        controlLayout.addWidget(self.cancelLoadButton)
        self.saveButton = QPushButton("Save PCAP")
        self.saveButton.clicked.connect(self.savePcapFile)
        controlLayout.addWidget(self.saveButton)
        self.clearButton = QPushButton("Clear Records")
        self.clearButton.clicked.connect(self.clearRecords)
        controlLayout.addWidget(self.clearButton)
        self.refreshInterfacesButton = QPushButton("Refresh Interfaces")
        self.refreshInterfacesButton.clicked.connect(self.populateInterfaces)
        controlLayout.addWidget(self.refreshInterfacesButton)
        controlLayout.addWidget(QLabel("Interface:"))
        self.interfaceDropdown = QComboBox()
        self.populateInterfaces()
        controlLayout.addWidget(self.interfaceDropdown)
        controlLayout.addWidget(QLabel("BPF Filter:"))
        self.bpfFilterInput = QLineEdit("tcp port 443")
        controlLayout.addWidget(self.bpfFilterInput)
        self.liveButton = QPushButton("Start Live Capture")
        self.liveButton.clicked.connect(self.toggleLiveCapture)
        controlLayout.addWidget(self.liveButton)
        self.labelButton = QPushButton("Label Fingerprint")
        self.labelButton.clicked.connect(self.labelSelectedFingerprint)
        self.labelButton.setEnabled(False)
        controlLayout.addWidget(self.labelButton)
        controlLayout.addStretch()
        mainLayout.addLayout(controlLayout)
        self.dataTable = QTableWidget(0, 8)
        self.dataTable.setHorizontalHeaderLabels([
            "Role", "Source", "Destination", "SNI", "JA3 Hash", "JA4 Hash",
            "JA3 Match", "JA4 Match"
        ])
        
        header = self.dataTable.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.dataTable.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.dataTable.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.dataTable.itemSelectionChanged.connect(self.displayRowDetails)
        mainLayout.addWidget(self.dataTable)
        self.detailsPane = QTextEdit()
        self.detailsPane.setReadOnly(True)
        self.detailsPane.setFixedHeight(120)
        self.detailsPane.setPlaceholderText("Select any handshake above to view raw metadata and JA3 string.")
        mainLayout.addWidget(self.detailsPane)

    def populateInterfaces(self):
        self.interfaceDropdown.clear()
        self.interfaceDropdown.addItem("Any (All Interfaces)", "Any")
        try:
            for iface in get_working_ifaces():
                self.interfaceDropdown.addItem(iface.name, iface.network_name)
        except Exception:
            self.interfaceDropdown.addItem("Default", "Default")

    def closeEvent(self, event):
        if self.pcapWorker and self.pcapWorker.isRunning():
            self.pcapWorker.stopCapture()
            self.pcapWorker.wait()
        if self.liveWorker and self.liveWorker.isRunning():
            self.liveWorker.stopCapture()
            self.liveWorker.wait()
        event.accept()

    def getDb(self):
        if self.fingerprintDb is None:
            self.fingerprintDb = FingerprintDB(str(self.dbPath))
        return self.fingerprintDb

    def selectPcapFile(self):
        if self.pcapWorker and self.pcapWorker.isRunning():
            return
        filePath, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP", str(self.pcapsDir), "PCAP Files (*.pcap *.pcapng)"
        )
        if filePath:
            self.clearRecords()
            self.loadedPcapPath = filePath
            self.loadButton.setEnabled(False)
            self.liveButton.setEnabled(False)
            self.cancelLoadButton.setEnabled(True)
            self.pcapWorker = PcapWorker(filePath, self.dbPath)
            self.pcapWorker.rowExtracted.connect(self.appendTableRow)
            self.pcapWorker.errorOccurred.connect(lambda err: self.detailsPane.setText(f"Error: {err}"))
            self.pcapWorker.captureFinished.connect(self.onCaptureFinished)
            self.pcapWorker.start()

    def cancelPcapLoad(self):
        if self.pcapWorker and self.pcapWorker.isRunning():
            self.pcapWorker.stopCapture()
            self.detailsPane.append("\nPCAP loading cancelled.")

    def onCaptureFinished(self, statsSummary):
        self.loadButton.setEnabled(True)
        self.liveButton.setEnabled(True)
        self.cancelLoadButton.setEnabled(False)
        currentText = self.detailsPane.toPlainText()
        self.detailsPane.setText(f"{currentText}\n\nCapture Finished.\n{statsSummary}")

    def toggleLiveCapture(self):
        if self.liveWorker and self.liveWorker.isRunning():
            self.liveWorker.stopCapture()
            self.liveButton.setText("Start Live Capture")
            self.loadButton.setEnabled(True)
        else:
            if self.pcapWorker and self.pcapWorker.isRunning():
                return
            selectedInterface = self.interfaceDropdown.currentData()
            currentFilter = self.bpfFilterInput.text()
            self.clearRecords()
            self.liveWorker = LiveCaptureWorker(
                selectedInterface, self.dbPath, currentFilter, packetBuffer=self.capturedPackets
            )
            self.liveWorker.rowExtracted.connect(self.appendTableRow)
            self.liveWorker.errorOccurred.connect(
                lambda errorMsg: self.detailsPane.setText(errorMsg)
            )
            self.liveWorker.captureFinished.connect(self.onCaptureFinished)
            self.liveWorker.start()
            self.liveButton.setText("Stop Live Capture")
            self.loadButton.setEnabled(False)
            self.cancelLoadButton.setEnabled(False)

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
            packetData["role"],
            packetData["source"],
            packetData["destination"],
            packetData["sni"],
            packetData["ja3Hash"],
            packetData["ja4Hash"],
            packetData["ja3Match"],
            packetData["ja4Match"],
        ]
        isClient = packetData["role"] == "Client"
        rowColor = QColor(0, 255, 0, 20) if isClient else QColor(0, 0, 255, 20)
        for colIdx, val in enumerate(columnValues):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            item.setBackground(rowColor)
            self.dataTable.setItem(currentRow, colIdx, item)
        self.dataTable.scrollToBottom()

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
                f"Role:       {entry['role']}\n"
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
            "Verified name:",
        )
        if not accepted or not label.strip():
            return
        try:
            db = self.getDb()
            pair = (
                ("ja3", "ja3Hash", "ja3Match", 6),
                ("ja4", "ja4Hash", "ja4Match", 7),
            )
            if entry.get("fingerprintKind") in ("ja3s", "ja4s"):
                pair = (
                    ("ja3s", "ja3Hash", "ja3Match", 6),
                    ("ja4s", "ja4Hash", "ja4Match", 7),
                )
            for kind, hashKey, matchKey, _ in pair:
                if entry.get(matchKey) == "Unknown":
                    db.enroll(entry[hashKey], kind, label)
        except (OSError, ValueError) as error:
            self.detailsPane.setText(f"Could not save fingerprint: {error}")
            return
        for matchKey, targetColumn in (("ja3Match", 6), ("ja4Match", 7)):
            if entry.get(matchKey) == "Unknown":
                entry[matchKey] = label.strip()
                newItem = QTableWidgetItem(entry[matchKey])
                newItem.setFlags(newItem.flags() & ~Qt.ItemFlag.ItemIsEditable)
                isClient = entry["role"] == "Client"
                newItem.setBackground(QColor(0, 255, 0, 20) if isClient else QColor(0, 0, 255, 20))
                self.dataTable.setItem(rowIndex, targetColumn, newItem)
        self.displayRowDetails()