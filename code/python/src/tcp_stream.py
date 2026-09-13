class TCPStream:
    """
    Manages the state and buffer for a single directional TCP flow.
    """
    def __init__(self):
        self.buffer = bytearray()
        
    def add_data(self, data):
        """Append raw TCP payload bytes to the buffer."""
        self.buffer.extend(data)
        
    def get_tls_record(self):
        """
        Inspects the buffer for a complete TLS Handshake record (content type 0x16).
        
        Skips past any non-Handshake records (0x14 Change Cipher Spec, 
        0x17 Application Data, etc.) so they don't poison the buffer.
        
        Returns the raw bytes of the Handshake record if complete, else None.
        """
        while len(self.buffer) >= 5:
            content_type = self.buffer[0]
            record_len = int.from_bytes(self.buffer[3:5], byteorder='big')
            total_len = 5 + record_len
            
            if content_type == 0x16:
                # This IS a Handshake record. Check if we have all the bytes.
                if len(self.buffer) >= total_len:
                    record_bytes = self.buffer[:total_len]
                    self.buffer = self.buffer[total_len:]
                    return bytes(record_bytes)
                else:
                    # Handshake record is incomplete. Wait for more data.
                    return None
            else:
                # This is NOT a Handshake (e.g., 0x14 CCS, 0x17 App Data).
                # We don't need it for JA3. Drain it from the buffer.
                if len(self.buffer) >= total_len:
                    # Complete non-handshake record — skip past it entirely.
                    self.buffer = self.buffer[total_len:]
                    # Loop again to check if there's a Handshake record behind it.
                else:
                    # Incomplete non-handshake record — wait for more data.
                    return None
        
        return None
