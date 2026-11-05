import os
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import AsyncSniffer, IP, IPv6, TCP, get_working_ifaces
from src.capture import read_pcap as readPcap, TCPReassembler, CaptureStats
from src.ja3 import (
    compute_ja3_hash as computeJa3Hash,
    compute_ja3_string as computeJa3String,
    compute_ja3s_hash as computeJa3sHash,
    compute_ja3s_string as computeJa3sString
)
from src.ja4 import (
    compute_ja4_string as computeJa4String,
    compute_ja4s_string as computeJa4sString
)
from src.db import FingerprintDB

def clientPacketData(result, clientHello, fingerprintDb):
    ja3Hash = computeJa3Hash(clientHello)
    ja4Hash = computeJa4String(clientHello)
    ja3Match = fingerprintDb.lookup(ja3Hash, "ja3") or "Unknown"
    ja4Match = fingerprintDb.lookup(ja4Hash, "ja4") or "Unknown"
    targetKind = "ja3" if ja3Match == "Unknown" else "ja4"
    targetHash = ja3Hash if targetKind == "ja3" else ja4Hash
    return {
        "role": "Client",
        "source": f"{result.src_ip}:{result.src_port}",
        "destination": f"{result.dst_ip}:{result.dst_port}",
        "sni": clientHello.server_name or "N/A",
        "ja3Hash": ja3Hash,
        "ja4Hash": ja4Hash,
        "ja3Match": ja3Match,
        "ja4Match": ja4Match,
        "fingerprintKind": targetKind,
        "fingerprintHash": targetHash,
        "ja3Raw": computeJa3String(clientHello),
    }

def serverPacketData(result, serverHello, fingerprintDb):
    ja3sHash = computeJa3sHash(serverHello)
    ja4sHash = computeJa4sString(serverHello)
    ja3sMatch = fingerprintDb.lookup(ja3sHash, "ja3s") or "Unknown"
    ja4sMatch = fingerprintDb.lookup(ja4sHash, "ja4s") or "Unknown"
    targetKind = "ja3s" if ja3sMatch == "Unknown" else "ja4s"
    targetHash = ja3sHash if targetKind == "ja3s" else ja4sHash
    return {
        "role": "Server",
        "source": f"{result.src_ip}:{result.src_port}",
        "destination": f"{result.dst_ip}:{result.dst_port}",
        "sni": "N/A",
        "ja3Hash": ja3sHash,
        "ja4Hash": ja4sHash,
        "ja3Match": ja3sMatch,
        "ja4Match": ja4sMatch,
        "fingerprintKind": targetKind,
        "fingerprintHash": targetHash,
        "ja3Raw": computeJa3sString(serverHello),
    }

class PcapWorker(QThread):
    rowExtracted = pyqtSignal(dict)
    captureFinished = pyqtSignal(str)
    errorOccurred = pyqtSignal(str)

    def __init__(self, pcapPath, dbPath):
        super().__init__()
        self.pcapPath = pcapPath
        self.dbPath = dbPath
        self.isCapturing = True

    def run(self):
        try:
            fingerprintDb = FingerprintDB(str(self.dbPath))
            captureStats = CaptureStats()
            if not os.path.exists(self.pcapPath) or os.path.getsize(self.pcapPath) < 24:
                self.errorOccurred.emit("Selected file is empty or corrupted.")
                return
            for result in readPcap(self.pcapPath, captureStats):
                if not self.isCapturing:
                    break
                if result.client_hello:
                    self.rowExtracted.emit(
                        clientPacketData(result, result.client_hello, fingerprintDb)
                    )
                if result.server_hello:
                    self.rowExtracted.emit(
                        serverPacketData(result, result.server_hello, fingerprintDb)
                    )
            self.captureFinished.emit(captureStats.summary())
        except Exception as e:
            self.errorOccurred.emit(str(e))

    def stopCapture(self):
        self.isCapturing = False

class LiveCaptureWorker(QThread):
    rowExtracted = pyqtSignal(dict)
    errorOccurred = pyqtSignal(str)
    captureFinished = pyqtSignal(str)

    def __init__(self, interfaceName, dbPath, bpfFilter, packetBuffer=None):
        super().__init__()
        self.interfaceName = interfaceName
        self.dbPath = dbPath
        self.bpfFilter = bpfFilter
        self.captureStats = CaptureStats()
        self.reassembler = TCPReassembler(self.captureStats)
        self.packetBuffer = packetBuffer
        self.isCapturing = True
        self.sniffer = None

    def processLivePacket(self, pkt):
        if self.packetBuffer is not None:
            self.packetBuffer.append(pkt)
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
                self.rowExtracted.emit(
                    clientPacketData(res, res.client_hello, self.fingerprintDb)
                )
            if res.server_hello:
                self.rowExtracted.emit(
                    serverPacketData(res, res.server_hello, self.fingerprintDb)
                )

    def run(self):
        try:
            self.fingerprintDb = FingerprintDB(str(self.dbPath))
            if self.interfaceName == "Any":
                ifaceArg = [iface.network_name for iface in get_working_ifaces()]
            elif self.interfaceName == "Default":
                ifaceArg = None
            else:
                ifaceArg = self.interfaceName
            self.sniffer = AsyncSniffer(
                iface=ifaceArg,
                filter=self.bpfFilter,
                prn=self.processLivePacket,
                store=False
            )
            self.sniffer.start()
            while self.isCapturing:
                self.msleep(100)
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()
            self.captureFinished.emit(self.captureStats.summary())
        except Exception as exceptionObject:
            self.errorOccurred.emit(f"Capture failed: {exceptionObject}")

    def stopCapture(self):
        self.isCapturing = False