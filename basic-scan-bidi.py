import dpkt
import socket
import struct
import collections

# ==================================================================================
# SPARK / NATURAL SELECTION 2 NETWORK REASSEMBLER (BIDIRECTIONAL)
# ==================================================================================
#
# SYNOPSIS:
# This script decodes the custom UDP protocol used by Spark engine games (NS2).
# It handles packet fragmentation, reliable stream reordering, and message reassembly.
#
# UPDATES:
# - Now processes both CLIENT and SERVER traffic.
# - Differentiates source based on Port Range (Server: 27000-27080).
# - Maintains separate reassembly buffers for each direction to prevent collision.
#
# DATA FORMAT SUMMARY:
# --------------------
# 1. Packet Header (7 Bytes):
#    [Magic: 4 bytes] (0xBA1BA24F) - Little Endian
#    [SessionID: 2 bytes] - Identifies the client connection
#    [Type & Padding: 1 byte] -> Bits 0-1 determine type:
#        0 = Reliable, 1 = Unreliable, 2 = Ack
#
# 2. Ping Header (4 Bytes) - Present in ALL packets after the main header:
#    [Seq: 1] [LastRecv: 1] [PPT: 1] [Loss: 1]
#
# 3. Type-Specific Headers:
#    - Reliable (Type 0):   [AckSeq: 1] [AckBits: 4] [ReliableSeq: 1]
#      * The ReliableSeq wraps at 255 (UInt8).
#    - Unreliable (Type 1): [Sequence: 4]
#      * The Unreliable Sequence is UInt32.
#
# 4. Payload Chunks (Loop until end of packet):
#    - Start Chunk: [Flag: 1] [TotalMsgLen: 3] [FragLen: 2] [Payload...]
#    - Continuation Chunk: [Flag: 1] [FragLen: 2] [Payload...]
#
# ==================================================================================

# --- Configuration ---
PCAP_FILE = 'sparknet-cap.pcapng' # Using .pcapng as per your last file

# --- Constants ---
MAX_RELIABLE_AHEAD = 10   # Gap tolerance for Reliable stream before reset
RELIABLE_SEQ_MOD = 256    # Reliable is UInt8
WINDOW_SIZE = 128         # Threshold for Old vs New packets (handle wrapping)

class MessageAssembler:
    """
    Stitches chunks together into a full message.
    """
    def __init__(self, name):
        self.name = name
        self.buffer = bytearray()
        self.total_len = 0
        self.active = False
        self.start_seq = -1

    def reset(self):
        self.buffer = bytearray()
        self.total_len = 0
        self.active = False
        self.start_seq = -1

    def ingest_chunk(self, is_start, total_msg_len, payload, packet_seq):
        # 1. New Start Chunk
        if is_start:
            if self.active:
                # We hit a new message start while still building one. 
                # The previous one is incomplete/dropped.
                self.reset()
            
            self.buffer = bytearray(payload)
            self.total_len = total_msg_len
            self.active = True
            self.start_seq = packet_seq

        # 2. Continuation Chunk
        else:
            if not self.active:
                return None # Orphan chunk (missed the start packet)
            
            self.buffer.extend(payload)

        # 3. Completion Check
        if self.active and len(self.buffer) >= self.total_len:
            final_data = self.buffer[:self.total_len]
            self.reset()
            return final_data
        
        return None

class ReliableStream:
    """
    Manages the reliable packet stream state, buffering, and ordering.
    """
    def __init__(self):
        self.next_seq = None
        self.packet_buffer = {} 
        self.assembler = MessageAssembler("Reliable")

    def process_packet(self, seq, data, session_id, source_tag):
        if self.next_seq is None: self.next_seq = seq

        diff = (seq - self.next_seq) % RELIABLE_SEQ_MOD

        # Case A: Exact Match
        if diff == 0:
            self._process_payload(seq, data, session_id, source_tag)
            self.next_seq = (self.next_seq + 1) % RELIABLE_SEQ_MOD
            self._check_buffer(session_id, source_tag)
            return

        # Case B: Old Packet (Ignore duplicate/late packets)
        if diff > WINDOW_SIZE: return

        # Case C: Gap
        if diff <= MAX_RELIABLE_AHEAD:
            self.packet_buffer[seq] = data
        else:
            # Critical Gap - Resync
            self.assembler.reset()
            self.packet_buffer.clear()
            self.next_seq = seq
            self._process_payload(seq, data, session_id, source_tag)
            self.next_seq = (self.next_seq + 1) % RELIABLE_SEQ_MOD

    def _check_buffer(self, session_id, source_tag):
        while self.next_seq in self.packet_buffer:
            data = self.packet_buffer.pop(self.next_seq)
            self._process_payload(self.next_seq, data, session_id, source_tag)
            self.next_seq = (self.next_seq + 1) % RELIABLE_SEQ_MOD

    def _process_payload(self, packet_seq, data, session_id, source_tag):
        parse_chunks_in_payload(data, packet_seq, self.assembler, "RELIABLE", session_id, source_tag)

class UnreliableStream:
    def __init__(self):
        self.last_seq = None
        self.assembler = MessageAssembler("Unreliable")

    def process_packet(self, seq, data, session_id, source_tag):
        # Logic: Unreliable packets often drop. 
        # If we skip a sequence, we cannot finish any message currently being built.
        if self.last_seq is not None:
            if seq != self.last_seq + 1:
                if self.assembler.active:
                    self.assembler.reset()
        
        self.last_seq = seq
        parse_chunks_in_payload(data, seq, self.assembler, "UNRELIABLE", session_id, source_tag)

def parse_chunks_in_payload(data, packet_seq, assembler, type_label, session_id, source_tag):
    cursor = 0
    while cursor < len(data):
        try:
            flag = data[cursor]
            cursor += 1
            
            is_start = False
            total_len = 0
            frag_len = 0
            
            if flag == 0xFF:
                # Continuation: Flag(1) + FragLen(2)
                frag_len = struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
            else:
                # Start: Flag(1) + TotalLen(3) + FragLen(2)
                if cursor + 5 > len(data): break
                b1, b2, b3 = data[cursor], data[cursor+1], data[cursor+2]
                cursor += 3
                total_len = b1 | (b2 << 8) | (b3 << 16)
                frag_len = struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
                is_start = True
            
            if cursor + frag_len > len(data):
                break # Truncated

            payload = data[cursor : cursor + frag_len]
            cursor += frag_len

            # Assemble
            completed_msg = assembler.ingest_chunk(is_start, total_len, payload, packet_seq)
            if completed_msg:
                # Format: [SERVER RELIABLE MSG] ...
                print(f"[{source_tag} {type_label} MSG] COMPLETE | Session {session_id} | PktSeq {packet_seq} | Size: {len(completed_msg)}")
                print(f"HEX: {completed_msg.hex()}")

        except struct.error:
            break

# --- Global Session State ---
# Key: (session_id, source_tag) -> Value: {'rel': ReliableStream, 'unrel': UnreliableStream}
sessions = {}

def get_streams(session_id, source_tag):
    key = (session_id, source_tag)
    if key not in sessions:
        sessions[key] = {
            'rel': ReliableStream(),
            'unrel': UnreliableStream()
        }
    return sessions[key]

def parse_udp_payload(data, source_tag):
    cursor = 0
    if len(data) < 7: return
    
    # Check Magic
    magic = struct.unpack_from('<I', data, cursor)[0]
    if magic != 0xBA1BA24F: return 
    
    # Get Session ID
    session_id = struct.unpack_from('<H', data, 4)[0]

    # Get Packet Type
    packet_type = data[6] & 0x03
    
    # Skip Common(7) + Ping(4)
    cursor = 11

    # Retrieve specific stream for this direction
    streams = get_streams(session_id, source_tag)

    if packet_type == 0: # Reliable
        if cursor + 6 > len(data): return
        # Skip AckSeq(1) + AckBits(4)
        cursor += 5
        rel_seq = data[cursor]
        cursor += 1
        
        payload = data[cursor:]
        streams['rel'].process_packet(rel_seq, payload, session_id, source_tag)

    elif packet_type == 1: # Unreliable
        if cursor + 4 > len(data): return
        # Unreliable Sequence is 4 bytes (UInt32)
        unrel_seq = struct.unpack_from('<I', data, cursor)[0]
        cursor += 4
        
        payload = data[cursor:]
        streams['unrel'].process_packet(unrel_seq, payload, session_id, source_tag)

def main():
    print(f"Reassembling messages from {PCAP_FILE}...")
    try:
        f = open(PCAP_FILE, 'rb')
        pcap = dpkt.pcapng.Reader(f)
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP): continue
                ip = eth.data
                
                # Filter Logic Removed. 
                # Instead, we identify source.
                
                if not isinstance(ip.data, dpkt.udp.UDP): continue
                udp = ip.data
                
                # Determine Source (Server vs Client)
                # Server Port Range: 27000 - 27080
                src_port = udp.sport
                
                if 27000 <= src_port <= 27080:
                    source_tag = "SERVER"
                else:
                    source_tag = "CLIENT"

                parse_udp_payload(udp.data, source_tag)

            except Exception:
                continue
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()