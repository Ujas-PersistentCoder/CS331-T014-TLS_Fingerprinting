import os
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import AsyncSniffer, IP, IPv6, TCP

from src.capture import read_pcap, TCPReassembler, CaptureStats
from src.ja3 import compute_ja3_hash, compute_ja3_string
from src.db import FingerprintDB

class PcapWorker(QThread):
    rowExtracted = pyqtSignal(dict)
    captureFinished = pyqtSignal(str)
    errorOccurred = pyqtSignal(str)

    def __init__(self, pcapPath, dbPath):
        super().__init__()
        self.pcapPath = pcapPath
        self.fingerprintDb = FingerprintDB(str(dbPath))
        self.captureStats = CaptureStats()

    def run(self):
        try:
            if not os.path.exists(self.pcapPath) or os.path.getsize(self.pcapPath) < 24:
                self.errorOccurred.emit("Selected file is empty or corrupted.")
                return

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
                        "ja3Raw": compute_ja3_string(clientHello),
                    }
                    self.rowExtracted.emit(packetData)

            self.captureFinished.emit(self.captureStats.summary())
        except Exception as e:
            self.errorOccurred.emit(str(e))

class LiveCaptureWorker(QThread):
    rowExtracted = pyqtSignal(dict)
    errorOccurred = pyqtSignal(str)

    def __init__(self, interfaceName, dbPath):
        super().__init__()
        self.interfaceName = interfaceName
        self.fingerprintDb = FingerprintDB(str(dbPath))
        self.captureStats = CaptureStats()
        self.reassembler = TCPReassembler(self.captureStats)
        self.sniffer = None
        self.isRunning = True

    def processLivePacket(self, pkt):
        if not (pkt.haslayer(TCP) and (pkt.haslayer(IP) or pkt.haslayer(IPv6))):
            return

        ipLayer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        tcpLayer = pkt[TCP]

        srcIp = str(ipLayer.src)
        dstIp = str(ipLayer.dst)
        srcPort = int(tcpLayer.sport)
        dstPort = int(tcpLayer.dport)
        seq = int(tcpLayer.seq)
        flags = int(tcpLayer.flags)
        payload = bytes(tcpLayer.payload)
        timestamp = float(pkt.time)

        results = self.reassembler.process_packet(
            srcIp, dstIp, srcPort, dstPort, seq, flags, payload, timestamp
        )

        for res in results:
            if res.client_hello:
                clientHello = res.client_hello
                ja3Hash = compute_ja3_hash(clientHello)
                match = self.fingerprintDb.lookup(ja3Hash) or "Unknown"

                packetData = {
                    "source": f"{res.src_ip}:{res.src_port}",
                    "destination": f"{res.dst_ip}:{res.dst_port}",
                    "sni": clientHello.server_name or "N/A",
                    "ja3Hash": ja3Hash,
                    "matchedClient": match,
                    "ja3Raw": compute_ja3_string(clientHello),
                }
                self.rowExtracted.emit(packetData)

    def run(self):
        try:
            # Scapy expects None to sniff all interfaces, not the literal string "Default"
            ifaceArg = None if self.interfaceName == "Default" else self.interfaceName

            self.sniffer = AsyncSniffer(
                iface=ifaceArg,
                filter="tcp port 443",
                prn=self.processLivePacket,
                store=False
            )
            self.sniffer.start()

            while self.isRunning:
                self.msleep(100)

            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()

        except Exception as exceptionObject:
            self.errorOccurred.emit(f"Capture failed (Run as Admin/Root?): {exceptionObject}")

    def stopCapture(self):
        self.isRunning = False
        self.wait()