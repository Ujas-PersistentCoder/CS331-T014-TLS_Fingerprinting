import os
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import AsyncSniffer, IP, IPv6, TCP
from src.capture import read_pcap, TCPReassembler, CaptureStats
from src.ja3 import compute_ja3_hash, compute_ja3_string, compute_ja3s_hash
from src.ja4 import compute_ja4_string, compute_ja4s_string
from src.db import FingerprintDB

def client_packet_data(result, client_hello, fingerprint_db):
    ja3_hash = compute_ja3_hash(client_hello)
    ja4_hash = compute_ja4_string(client_hello)
    ja3_match = fingerprint_db.lookup(ja3_hash, "ja3") or "Unknown"
    ja4_match = fingerprint_db.lookup(ja4_hash, "ja4") or "Unknown"
    target_kind = "ja3" if ja3_match == "Unknown" else "ja4"
    target_hash = ja3_hash if target_kind == "ja3" else ja4_hash
    return {
        "source": f"{result.src_ip}:{result.src_port}",
        "destination": f"{result.dst_ip}:{result.dst_port}",
        "sni": client_hello.server_name or "N/A",
        "ja3Hash": ja3_hash,
        "ja4Hash": ja4_hash,
        "ja3Match": ja3_match,
        "ja4Match": ja4_match,
        "fingerprintKind": target_kind,
        "fingerprintHash": target_hash,
        "ja3Raw": compute_ja3_string(client_hello),
    }

def server_packet_data(result, server_hello, fingerprint_db):
    ja3s_hash = compute_ja3s_hash(server_hello)
    ja4s_hash = compute_ja4s_string(server_hello)
    ja3s_match = fingerprint_db.lookup(ja3s_hash, "ja3s") or "Unknown"
    ja4s_match = fingerprint_db.lookup(ja4s_hash, "ja4s") or "Unknown"
    target_kind = "ja3s" if ja3s_match == "Unknown" else "ja4s"
    target_hash = ja3s_hash if target_kind == "ja3s" else ja4s_hash
    return {
        "source": f"{result.src_ip}:{result.src_port}",
        "destination": f"{result.dst_ip}:{result.dst_port}",
        "sni": "N/A",
        "ja3Hash": ja3s_hash,
        "ja4Hash": ja4s_hash,
        "ja3Match": ja3s_match,
        "ja4Match": ja4s_match,
        "fingerprintKind": target_kind,
        "fingerprintHash": target_hash,
        "ja3Raw": "N/A",
    }

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
                    self.rowExtracted.emit(
                        client_packet_data(result, result.client_hello, self.fingerprintDb)
                    )
                if result.server_hello:
                    self.rowExtracted.emit(
                        server_packet_data(result, result.server_hello, self.fingerprintDb)
                    )
            self.captureFinished.emit(self.captureStats.summary())
        except Exception as e:
            self.errorOccurred.emit(str(e))

class LiveCaptureWorker(QThread):
    rowExtracted = pyqtSignal(dict)
    errorOccurred = pyqtSignal(str)

    def __init__(self, interfaceName, dbPath, packetBuffer=None):
        super().__init__()
        self.interfaceName = interfaceName
        self.fingerprintDb = FingerprintDB(str(dbPath))
        self.captureStats = CaptureStats()
        self.reassembler = TCPReassembler(self.captureStats)
        self.sniffer = None
        self.isRunning = True
        self.packetBuffer = packetBuffer

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
                    client_packet_data(res, res.client_hello, self.fingerprintDb)
                )
            if res.server_hello:
                self.rowExtracted.emit(
                    server_packet_data(res, res.server_hello, self.fingerprintDb)
                )

    def run(self):
        try:
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