import dpkt
import socket
import struct
import collections
import os

from speex_decoder import (
    decode_speex_bundle,
    append_pcm,
    flush_map,
    cleanup
)

# ==================================================================================
# CONFIGURATION & GLOBALS
# ==================================================================================
PCAP_FILE = 'sparknet-cap.pcapng'
DATA_DIR = 'data'

# Global Map Load Counter
MAP_LOAD_COUNT = 0

# Create data directory if not exists
os.makedirs(DATA_DIR, exist_ok=True)

# ==================================================================================
# USER PROCESSING HOOK
# ==================================================================================
def on_message_reassembled(data, direction, stream, session_id, seq):
    """
    Hook called when a full message is reassembled.
    """
    global MAP_LOAD_COUNT
    msg_len = len(data)
    if msg_len == 0:
        return

    # --- 1. DETECT MAP LOAD (Client -> Server, Reliable, Data=03 01) ---
    if direction == "CLIENT" and stream == "RELIABLE":
        if msg_len == 2 and data == b'\x03\x01':
            if (MAP_LOAD_COUNT > 0):
                # Flush WAVs for the map we just finished collecting
                try:
                    flush_map(MAP_LOAD_COUNT, DATA_DIR)
                except Exception as e:
                    print(f"[WAV Flush Error] {e}")

            MAP_LOAD_COUNT += 1
            print(f"\n[EVENT] Map Load Finished! Global Count: {MAP_LOAD_COUNT}\n")
            return

    # --- 2. DETECT VOICE / STATE (Server -> Client, Unreliable, OpCode=0x05) ---
    op_code = data[0]

    if direction == "SERVER" and stream == "UNRELIABLE" and op_code == 0x05:
        parse_voice_and_state(data, session_id)


def parse_voice_and_state(data, session_id):
    """
    Parses Type 5 Packet: Voice Data + Optional State Snapshot

    For each voice payload:
      - decode Speex bundle -> PCM int16
      - append to per-(map,player,channel) PCM buffer
    """
    cursor = 1  # Skip OpCode (0x05)

    if len(data) < 3:
        return  # Too short for voice count

    try:
        # Read Voice Packet Count (2 bytes)
        voice_count = struct.unpack_from('<H', data, cursor)[0]
        cursor += 2

        for _ in range(voice_count):
            if cursor + 3 > len(data):
                break  # Safety check

            # Peek at PlayerID (2 bytes) and ChannelID (1 byte)
            player_id = struct.unpack_from('<H', data, cursor)[0]
            channel_id = data[cursor + 2]

            # --- DETERMINE HEADER FORMAT ---
            if channel_id == 0x01:
                # Standard: Header is 5 bytes
                # [ID:2][Ch:1][Len:2]
                header_size = 5
                if cursor + header_size > len(data):
                    break
                data_len = struct.unpack_from('<H', data, cursor + 3)[0]

            elif channel_id == 0x02:
                # Positional: Header is 17 bytes
                # [ID:2][Ch:1][Pos:12][Len:2]
                header_size = 17
                if cursor + header_size > len(data):
                    break
                data_len = struct.unpack_from('<H', data, cursor + 15)[0]

            elif channel_id == 0x03:
                # Positional + Target: Header is 19 bytes
                # [ID:2][Ch:1][Pos:12][Target:2][Len:2]
                header_size = 19
                if cursor + header_size > len(data):
                    break
                data_len = struct.unpack_from('<H', data, cursor + 17)[0]

            else:
                print(f"[Voice Error] Unknown Channel ID: 0x{channel_id:02X} at offset {cursor}")
                return

            # --- EXTRACT SPEEX DATA ---
            payload_start = cursor + header_size
            payload_end = payload_start + data_len

            if payload_end > len(data):
                print(f"[Voice Error] Truncated payload. Need {data_len}, have {len(data) - payload_start}")
                break

            speex_data = data[payload_start:payload_end]

            # --- DECODE -> APPEND PCM ---
            try:
                pcm = decode_speex_bundle(player_id, channel_id, speex_data)
                if pcm:
                    append_pcm(MAP_LOAD_COUNT, player_id, channel_id, pcm)
            except Exception as e:
                print(f"[Speex Decode Error] map={MAP_LOAD_COUNT} player={player_id} ch={channel_id}: {e}")

            # Advance Cursor
            cursor = payload_end

        # --- CHECK FOR STATE SNAPSHOT ---
        if cursor < len(data):
            remaining = len(data) - cursor
            print(f"[Snapshot] State Snapshot Present after voice data: ({remaining} bytes remaining)")
            # state_data = data[cursor:]

    except struct.error:
        print("[Parse Error] Malformed Voice Packet structure")



# ==================================================================================
# NS2 Fragment Assembler
# ==================================================================================

# --- Constants ---
MAX_RELIABLE_AHEAD = 10   
RELIABLE_SEQ_MOD = 256    
WINDOW_SIZE = 128         

class MessageAssembler:
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
        if is_start:
            if self.active: self.reset()
            self.buffer = bytearray(payload)
            self.total_len = total_msg_len
            self.active = True
            self.start_seq = packet_seq
        else:
            if not self.active: return None
            self.buffer.extend(payload)

        if self.active and len(self.buffer) >= self.total_len:
            final_data = bytes(self.buffer[:self.total_len])
            self.reset()
            return final_data
        return None

class ReliableStream:
    def __init__(self):
        self.next_seq = None
        self.packet_buffer = {} 
        self.assembler = MessageAssembler("Reliable")

    def process_packet(self, seq, data, session_id, source_tag):
        if self.next_seq is None: self.next_seq = seq
        diff = (seq - self.next_seq) % RELIABLE_SEQ_MOD

        if diff == 0:
            self._process_payload(seq, data, session_id, source_tag)
            self.next_seq = (self.next_seq + 1) % RELIABLE_SEQ_MOD
            self._check_buffer(session_id, source_tag)
            return

        if diff > WINDOW_SIZE: return

        if diff <= MAX_RELIABLE_AHEAD:
            self.packet_buffer[seq] = data
        else:
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
        if self.last_seq is not None:
            if seq != self.last_seq + 1:
                if self.assembler.active: self.assembler.reset()
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
                frag_len = struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
            else:
                if cursor + 5 > len(data): break
                b1, b2, b3 = data[cursor], data[cursor+1], data[cursor+2]
                cursor += 3
                total_len = b1 | (b2 << 8) | (b3 << 16)
                frag_len = struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
                is_start = True
            
            if cursor + frag_len > len(data): break

            payload = data[cursor : cursor + frag_len]
            cursor += frag_len

            completed_msg = assembler.ingest_chunk(is_start, total_len, payload, packet_seq)
            
            if completed_msg:
                on_message_reassembled(
                    data=completed_msg, 
                    direction=source_tag, 
                    stream=type_label, 
                    session_id=session_id, 
                    seq=packet_seq
                )

        except struct.error:
            break

# --- Global Session State ---
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
    
    magic = struct.unpack_from('<I', data, cursor)[0]
    if magic != 0xBA1BA24F: return 
    
    session_id = struct.unpack_from('<H', data, 4)[0]
    packet_type = data[6] & 0x03
    cursor = 11
    
    streams = get_streams(session_id, source_tag)

    if packet_type == 0: # Reliable
        if cursor + 6 > len(data): return
        cursor += 5
        rel_seq = data[cursor]
        cursor += 1
        payload = data[cursor:]
        streams['rel'].process_packet(rel_seq, payload, session_id, source_tag)

    elif packet_type == 1: # Unreliable
        if cursor + 4 > len(data): return
        unrel_seq = struct.unpack_from('<I', data, cursor)[0]
        cursor += 4
        payload = data[cursor:]
        streams['unrel'].process_packet(unrel_seq, payload, session_id, source_tag)

def main():
    print(f"Decoding {PCAP_FILE}...")
    print(f"Voice data will be saved to '{DATA_DIR}/'")
    try:
        f = open(PCAP_FILE, 'rb')
        pcap = dpkt.pcapng.Reader(f)
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP): continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP): continue
                udp = ip.data
                
                # Tagging based on Port 27000-27080
                if 27000 <= udp.sport <= 27080: source_tag = "SERVER"
                else: source_tag = "CLIENT"

                parse_udp_payload(udp.data, source_tag)
            except Exception: continue
    except Exception as e:
        print(f"Error: {e}")
        
    # ---- FINAL FLUSH ON PROGRAM EXIT ----
    try:
        flush_map(MAP_LOAD_COUNT, DATA_DIR)
    except Exception as e:
        print(f"[WAV Flush Error] {e}")

    # ---- CLEAN UP SPEEX DECODERS ----
    cleanup()

if __name__ == '__main__':
    main()