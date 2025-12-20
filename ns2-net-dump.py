import dpkt
import socket
import struct
import collections
import os
import zlib
import argparse
import sys
from utils import BinaryReader  # Import from your new file

from speex_decoder import (
    decode_speex_bundle,
    append_pcm,
    flush_map,
    cleanup
)

# ==================================================================================
# CONFIGURATION & GLOBALS
# ==================================================================================
DATA_DIR = 'data'
MAX_PRINT_FILES = 10  # Limit console spam for consistency checker

# Type 7 Mode values
CLIENT_MODES = {
    0x1: "WaitingForAuth",
    0x2: "ConnectAttempt",
    0x3: "Authenticating",
    0x4: "Connecting",
    0x5: "WaitingForServer",
    0x6: "Connected",
    0x7: "Disconnecting",
    0x8: "Disconnected",
    0x9: "DownloadingLevel"
}

# Global Flag for Voice Dumping (Set via CLI args)
DUMP_VOICE = False

os.makedirs(DATA_DIR, exist_ok=True)

# Data Structure to hold parsed state
class GameState:
    def __init__(self):
        self.map_load_count = 0
        self.map_name = None
        self.is_secure = False
        self.is_thunderdome = False
        self.properties = {}
        self.backup_urls = []
        self.mods = []
        self.consistency_files = [] # List of tuples (filename, hash)
        self.password = None
        
        self.net_class_checksums = [] # List of {'class_id': int, 'checksum': int}
        self.net_class_names = []     # List of {'class_name': str, 'class_id': int} Network Class
        
        self.network_messages = [] # Network Messages Table
        
        self.precache_string_table = [] # List of {'id': int, 'string': str}
        self.precache_model_table = [] # List of {'id': int, 'path': str}
        self.precache_animation_table = [] # List of {'id': int, 'path': str}
        self.precache_sound_table = [] # List of {'id': int, 'path': str}
        self.precache_cinematic_table = [] # List of {'id': int, 'path': str}
        
        # Authentication
        self.auth_salt = None
        self.auth_enabled = False
        self.server_port = None
        self.server_ip = None
        self.server_steam_id = None
        
        self.server_mode = "None"

# Global Instance
initial_game_state = GameState()

# ==================================================================================
# PACKET HANDLERS
# ==================================================================================

def handle_map_load_finished(data):
    """Handles Client -> Server 'Map Load Finished' signal (0x03 0x01)."""
    if len(data) == 2 and data == b'\x03\x01':
        # Only flush WAVs if voice dumping is enabled
        if DUMP_VOICE and initial_game_state.map_load_count > 0:
            try:
                flush_map(initial_game_state.map_load_count, DATA_DIR)
            except Exception as e:
                print(f"[WAV Flush Error] {e}")

        initial_game_state.map_load_count += 1
        print(f"\n[EVENT] Map Load Finished! Global Count: {initial_game_state.map_load_count}\n")
        return True
    return False

def parse_consistency_checker(reader, num_files):
    """
    Parses the M4::ConsistencyChecker block.
    
    The Consistency Checker validates client file integrity using a 'Swizzled' MD5 hash.
    
    MECHANISM:
    1. The server generates a random 'Swizzle Key' (4 bytes). Each byte in this key 
       represents an index (0-15) pointing to a byte in a standard 16-byte MD5 hash.
    2. For every file the server calculates the full MD5.
    3. Instead of sending the full 16-byte MD5, it extracts only the 4 bytes 
       indicated by the Swizzle Key indices.
    
    WHY:
    - Bandwidth: Reduces payload from ~400KB (16 bytes/file) to ~100KB (4 bytes/file).
    - Security: The random indices make it harder to spoof valid files without 
      possessing the actual file content, as the required bytes change every connection.
    """
    print("  --- Consistency Checker ---")
    
    # 1. Restrict Patterns
    num_patterns = reader.read_uint32()
    print(f"  Restrict Patterns ({num_patterns}):")
    for _ in range(num_patterns):
        pattern = reader.read_string_len()
        print(f"    - {pattern}")
   
    # 2. File Count
    real_num_files = reader.read_uint32()
    
    # 3. Swizzle Key
    swizzle = reader.read_bytes(4)
    print(f"  Files Checked: {real_num_files} | Swizzle Key: {swizzle.hex().upper()}")

    # 4. Partial Hashes
    partial_hashes = []
    for _ in range(real_num_files):
        p_hash = reader.read_bytes(4)
        partial_hashes.append(p_hash.hex().upper())

    # 5. Compressed Filenames
    names_uncomp_size = reader.read_uint32()
    names_comp_size = reader.read_uint32()
    names_comp_data = reader.read_bytes(names_comp_size)
    
    print(f"  Filename Block: {names_comp_size} bytes (Uncompressed: {names_uncomp_size})")

    # Decompress and Parse Names
    initial_game_state.consistency_files = [] # Reset
    try:
        if names_comp_size > 0:
            names_blob = zlib.decompress(names_comp_data)
            names_reader = BinaryReader(names_blob)
            
            print(f"  File Manifest (Displaying first {MAX_PRINT_FILES} of {real_num_files}):")
            
            for i in range(real_num_files):
                f_name = names_reader.read_string_len()
                f_hash = partial_hashes[i] if i < len(partial_hashes) else "????"
                
                # Store in data structure
                initial_game_state.consistency_files.append({'name': f_name, 'hash': f_hash})

                # Print only first N
                if i < MAX_PRINT_FILES:
                    print(f"    [{i:03}] {f_name:<50} | Hash: {f_hash}")
                elif i == MAX_PRINT_FILES:
                    print(f"    ... (remaining {real_num_files - MAX_PRINT_FILES} files hidden) ...")
                    
    except Exception as e:
        print(f"  [!] Failed to decompress filenames: {e}")

def parse_class_table(reader):
    """
    ClassTable.
    
    This function synchronizes the dictionary of Network Classes between Server and Client.
    
    Table 1: Class Checksums
    - Maps Class ID -> CRC32 Checksum.
    - Ensures the Client's C++ class layout matches the Server's (prevents crashes/desyncs).
    
    Table 2: Class Names
    - Maps Class Name (String) -> Class ID.
    - Allows the engine to instantiate the correct entity when it receives a Class ID in future packets.
    """
    print("  --- Class Table ---")

    # ==========================================================================
    # 1. Network Class Checksums (ID -> Checksum)
    # ==========================================================================
    checksum_count = reader.read_uint16()
    print(f"  Network Class Checksums ({checksum_count}):")
    
    initial_game_state.net_class_checksums = []
    for i in range(checksum_count):
        cls_id = reader.read_uint16()
        cls_sum = reader.read_uint32()
        
        initial_game_state.net_class_checksums.append({'class_id': cls_id, 'checksum': cls_sum})
        
        if i < 10:
            print(f"    [{i}] Class ID: {cls_id:<5} | Checksum: {cls_sum:08X}")
    
    if checksum_count > 10:
        print(f"    ... ({checksum_count - 10} entries hidden)")

    # ==========================================================================
    # 2. Network Class Names (String -> ID)
    # ==========================================================================
    name_count = reader.read_uint16()
    print(f"  Network Class Names ({name_count}):")
    
    initial_game_state.net_class_names = []
    for i in range(name_count):
        # 00450adc: WriteNullTerminatedString
        cls_name = reader.read_string_null()
        # 00450af1: WriteUInt16
        cls_id = reader.read_uint16()
        
        initial_game_state.net_class_names.append({'class_name': cls_name, 'class_id': cls_id})
        
        if i < 10:
            print(f"    [{i}] ID: {cls_id:<5} | Name: {cls_name}")

    if name_count > 10:
        print(f"    ... ({name_count - 10} entries hidden)")

def parse_message_table(reader):
    """
    MessageTable.
    """
    print("  --- Message Table ---")

    # 0044ac7e: WriteUInt16(count)
    msg_count = reader.read_uint16()
    print(f"  Network Messages ({msg_count}):")
    
    initial_game_state.network_messages = []
    
    for i in range(msg_count):
        # Implicit Index: The loop counter 'i' IS the Message ID (+1 usually)
        msg_id = i + 1  # Spark Engine usually uses 1-based IDs for messages
        
        # 0044acba: WriteNullTerminatedString(name)
        msg_name = reader.read_string_null()
        
        # 0044accc: WriteUInt32(checksum)
        msg_sum = reader.read_uint32()
        
        initial_game_state.network_messages.append({
            'id': msg_id, 
            'name': msg_name, 
            'checksum': msg_sum
        })
        
        if i < 10:
            print(f"    [ID {msg_id}] {msg_name:<30} | Checksum: {msg_sum:08X}")
            
    if msg_count > 10:
        print(f"    ... ({msg_count - 10} messages hidden)")

def parse_generic_string_table(reader, target_list, label):
    """
    Parses a generic StringTable or ResourceTable.
    Used for Locations, Models, Sounds, Cinematics, etc.
    
    Structure:
    - Count (UInt16)
    - Loop:
      - Null-Terminated String (Path or Name)
    
    Items are implicitly indexed by their order in the list (usually 1-based).
    """
    print(f"  --- {label} ---")

    # Read Count
    count = reader.read_uint16()
    print(f"  Entries ({count}):")
    
    # Clear existing list (if any) and start fresh
    target_list.clear()
    
    for i in range(count):
        # Implicit Index
        # Note: In C++ vectors are 0-indexed. 
        # Spark networking often uses 1-based IDs for assets, but let's just track the index 'i'.
        res_id = i + 1 
        
        # Read String
        res_val = reader.read_string_null()
        
        target_list.append({
            'id': res_id, 
            'val': res_val
        })
        
        if i < 5:
            print(f"    [{i}] {res_val}")
            
    if count > 5:
        print(f"    ... ({count - 5} entries hidden)")

def handle_authentication_packet(data):
    """
    Handles Server -> Client 'Authentication' packet (Opcode 0x01).
    Routine: M4::ServerGame::SendAuthenticationPacket
    """
    # Initialize reader
    reader = BinaryReader(data)
    
    # 1. Skip Opcode (0x01)
    opcode = reader.read_uint8()
    
    # 3. Read Password Salt
    # Definition: M4::UInt8 passwordSalt[0xa]; -> 10 Bytes
    # Code: M4::BinaryWriter::WriteBlock(..., numBytes: 0xa)
    SALT_SIZE = 10
    salt_bytes = reader.read_bytes(SALT_SIZE)
    initial_game_state.auth_salt = salt_bytes.hex().upper()
    
    # 4. Read Authentication Enabled Flag
    # Code: M4::BinaryWriter::WriteBool(...) -> Writes UInt32 (4 bytes)
    initial_game_state.auth_enabled = reader.read_bool()
    
    print(f"\n[Packet 0x04] AUTHENTICATION:")
    print(f"  Salt: {initial_game_state.auth_salt}")
    print(f"  Auth Enabled: {initial_game_state.auth_enabled}")
    
    # 5. Conditional Server Details
    # Code: if (this->m_authenticationEnabled != 0)
    if initial_game_state.auth_enabled:
        # Code: WriteUInt32(Port)
        initial_game_state.server_port = reader.read_uint32()
        
        # Code: WriteUInt32(Address)
        # Note: Address is likely packed UInt32. We convert to String IP.
        raw_addr = reader.read_uint32()
        try:
            # Convert Little Endian UInt32 back to bytes, then standard IPv4 string
            packed_addr = struct.pack('<I', raw_addr)
            initial_game_state.server_ip = socket.inet_ntoa(packed_addr)
        except:
            initial_game_state.server_ip = f"Unknown({raw_addr})"
            
        # Code: WriteUInt64(Id) -> SteamID
        initial_game_state.server_steam_id = reader.read_uint64()
        
        print(f"  Service Port: {initial_game_state.server_port}")
        print(f"  Service Address: {initial_game_state.server_ip}")
        print(f"  Steam ID: {initial_game_state.server_steam_id} (0x{initial_game_state.server_steam_id:016X})")

def handle_connecting_packet(data):
    """Handles Server -> Client 'Connecting' packet (0x02)."""
    try:
        # Header: [Uncompressed Size (4 bytes)] [Compressed Size (4 bytes)]
        if len(data) < 9: return

        uncompressed_size = struct.unpack('<I', data[1:5])[0]
        compressed_size = struct.unpack('<I', data[5:9])[0]
        compressed_payload = data[9:]

        if len(compressed_payload) != compressed_size:
            print(f"[Packet 0x02] Warning: Compressed size mismatch.")

        try:
            decompressed_data = zlib.decompress(compressed_payload)
        except Exception as e:
            print(f"[Packet 0x02] Zlib Error: {e}")
            return

        # --- START PARSING ---
        reader = BinaryReader(decompressed_data)

        # Basic Info
        initial_game_state.map_name = reader.read_string_null()
        _ = reader.read_uint32() # unknown_1
        initial_game_state.is_secure = reader.read_bool()
        initial_game_state.is_thunderdome = reader.read_bool()

        print(f"\n[Packet 0x02] CONNECTING:")
        print(f"  Map: {initial_game_state.map_name}")
        print(f"  Secure: {initial_game_state.is_secure} | Thunderdome: {initial_game_state.is_thunderdome}")

        # Properties
        prop_count = reader.read_uint16()
        initial_game_state.properties = {}
        print(f"  Properties ({prop_count}):")
        for _ in range(prop_count):
            key = reader.read_string_len()
            val = reader.read_string_len()
            initial_game_state.properties[key] = val
            print(f"    {key}: {val}")

        # Backup URLs
        url_count = reader.read_uint16()
        initial_game_state.backup_urls = []
        print(f"  Backup URLs ({url_count}):")
        for _ in range(url_count):
            url = reader.read_string_len()
            initial_game_state.backup_urls.append(url)
            print(f"    {url}")

        # Mods
        mod_count = reader.read_uint16()
        initial_game_state.mods = []
        print(f"  Mods ({mod_count}):")
        for _ in range(mod_count):
            mod_id = reader.read_uint64()
            mod_crc = reader.read_uint32()
            mod_name = "<Workshop Mod>"
            if mod_id == 0:
                mod_name = reader.read_string_null()
            
            initial_game_state.mods.append({'id': mod_id, 'crc': mod_crc, 'name': mod_name})
            print(f"    ID: {mod_id} | CRC: {mod_crc:08X} | Name: {mod_name}")

        # Consistency Checker
        parse_consistency_checker(reader, 0) 

        # Disable Client Mods
        initial_game_state.client_mods_disabled = reader.read_bool()
        
        # Server Name
        initial_game_state.server_name = reader.read_string_null()
        
        print(f"  Client Mods Disabled: {initial_game_state.client_mods_disabled}")
        print(f"  Server Name: {initial_game_state.server_name}")

        # Network Class Table
        parse_class_table(reader)

        # Message Table
        parse_message_table(reader)
        
        # ==================================================================
        # ASSET PRECACHE TABLES (Refactored to Generic Function)
        # ==================================================================
        
        # 1. Precache String Table (Map Locations)
        parse_generic_string_table(
            reader, 
            initial_game_state.precache_string_table, 
            "Precache String Table (Locations)"
        )
        
        # 2. Precache Model Table
        parse_generic_string_table(
            reader, 
            initial_game_state.precache_model_table, 
            "Precache Model Table"
        )

        # 3. Precache Animation Table
        parse_generic_string_table(
            reader, 
            initial_game_state.precache_animation_table, 
            "Precache Animation Table"
        )
        
        # 4. Precache Sound Table
        parse_generic_string_table(
            reader, 
            initial_game_state.precache_sound_table, 
            "Precache Sound Table"
        )

        # 5. Precache Cinematic Table
        parse_generic_string_table(
            reader, 
            initial_game_state.precache_cinematic_table, 
            "Precache Cinematic Table"
        )

        # Check for any remaining bytes (debugging)
        if reader.offset < len(reader.data):
             remaining = len(reader.data) - reader.offset
             print(f"  [Debug] {remaining} bytes remaining in packet stream.")

    except Exception as e:
        print(f"[Packet 0x02] Error parsing: {e}")
        import traceback
        traceback.print_exc()

def parse_voice_and_state(data, session_id):
    """
    Parses Type 5 Packet: Voice Data + Optional State Snapshot.
    
    Logic:
    1. Parse the voice packet headers (ID, Channel, Length) to find where they end.
    2. If --dump-voice is ON: Decode Speex -> WAV.
    3. If --dump-voice is OFF: Skip over voice bytes.
    4. Check for State Snapshot data appearing after the voice payload.
    """
    cursor = 1  # Skip OpCode (0x05)
    if len(data) < 3: return

    try:
        # Read Voice Packet Count (2 bytes)
        voice_count = struct.unpack_from('<H', data, cursor)[0]
        cursor += 2

        for _ in range(voice_count):
            if cursor + 3 > len(data): break 
            player_id = struct.unpack_from('<H', data, cursor)[0]
            channel_id = data[cursor + 2]

            # --- DETERMINE HEADER FORMAT ---
            header_size = 0
            data_len = 0
            
            if channel_id == 0x01: # Standard
                header_size = 5
                if cursor + header_size > len(data): break
                data_len = struct.unpack_from('<H', data, cursor + 3)[0]
            elif channel_id == 0x02: # Positional
                header_size = 17
                if cursor + header_size > len(data): break
                data_len = struct.unpack_from('<H', data, cursor + 15)[0]
            elif channel_id == 0x03: # Positional + Target
                header_size = 19
                if cursor + header_size > len(data): break
                data_len = struct.unpack_from('<H', data, cursor + 17)[0]
            else:
                # print(f"[Voice Error] Unknown Channel ID: 0x{channel_id:02X}")
                return

            payload_start = cursor + header_size
            payload_end = payload_start + data_len

            if payload_end > len(data): break
            
            # --- CONDITIONAL DECODING ---
            if DUMP_VOICE:
                speex_data = data[payload_start:payload_end]
                try:
                    pcm = decode_speex_bundle(player_id, channel_id, speex_data)
                    if pcm:
                        append_pcm(initial_game_state.map_load_count, player_id, channel_id, pcm)
                except Exception as e:
                    pass
            
            # Always advance cursor so we can find the Snapshot
            cursor = payload_end

        # State Snapshot Check
        if cursor < len(data):
            remaining = len(data) - cursor
            #print(f"[Snapshot] Present ({remaining} bytes)")

    except struct.error:
        pass

def parse_mode_packet(data):
    """
    Handles Server -> Client 'OnMode' packet (Opcode 0x07).
    Sets the current connection state of the client.
    """
    reader = BinaryReader(data)
    
    # 1. Skip Opcode (0x07)
    opcode = reader.read_uint8()
    
    # 2. Read Mode ID (1 Byte)
    mode_id = reader.read_uint8()
    
    # Lookup name
    mode_name = CLIENT_MODES.get(mode_id, f"Unknown_0x{mode_id:02X}")
    initial_game_state.server_mode = mode_id
    
    print(f"\n[Packet 0x07] SET MODE: {mode_name} ({mode_id})")
    
def parse_disconnect_packet(data):
    """
    Handles Server -> Client 'Disconnect' packet (System Opcode 0x02).
    Structure: [Opcode: 1] [Reason: 4] [Message: NullString]
    """
    reader = BinaryReader(data)
    
    # 1. Skip Opcode (0x02)
    opcode = reader.read_uint8()
    
    # 2. Read Reason (UInt32)
    reason_code = reader.read_uint32()
    
    # 3. Read Message (Null Terminated String)
    message = reader.read_string_null()
    
    print(f"\n[Packet 0x02] DISCONNECT (System):")
    print(f"  Reason Code: {reason_code}")
    print(f"  Message: {message}")

# ==================================================================================
# USER PROCESSING HOOK (Main Dispatcher)
# ==================================================================================
def on_message_reassembled(data, direction, stream, session_id, seq, is_system=False):
    msg_len = len(data)
    if msg_len == 0: return

    # 1. Map Load Detection
    if direction == "CLIENT" and stream == "RELIABLE":
        if handle_map_load_finished(data):
            return

    op_code = data[0]

    # --- SERVER RELIABLE PACKETS ---
    if direction == "SERVER" and stream == "RELIABLE":
        
        # Opcode 0x02: Collision Handler
        if op_code == 0x02:
            if is_system:
                # System Packet 0x02 -> Disconnect
                handle_disconnect_packet(data)
            else:
                # Normal Packet 0x02 -> Connecting
                handle_connecting_packet(data)

        # 0x04: Authentication
        elif op_code == 0x01:
            handle_authentication_packet(data)
            
        # 0x07: OnMode
        elif op_code == 0x07:
            parse_mode_packet(data)
    
    # 5. Voice / State Packet
    if direction == "SERVER" and stream == "UNRELIABLE" and op_code == 0x05:
        # We always process this packet to advance past voice data 
        # and potentially find the State Snapshot at the end.
        parse_voice_and_state(data, session_id)


# ==================================================================================
# NS2 Fragment Assembler
# ==================================================================================

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
        self.is_system = False

    def reset(self):
        self.buffer = bytearray()
        self.total_len = 0
        self.active = False
        self.start_seq = -1
        self.is_system = False

    def ingest_chunk(self, is_start, is_system, total_msg_len, payload, packet_seq):
        if is_start:
            if self.active: self.reset()
            self.buffer = bytearray(payload)
            self.total_len = total_msg_len
            self.active = True
            self.start_seq = packet_seq
            self.is_system = is_system
        else:
            if not self.active: return None
            self.buffer.extend(payload)

        if self.active and len(self.buffer) >= self.total_len:
            final_data = bytes(self.buffer[:self.total_len])
            was_system = self.is_system
            self.reset()
            return final_data, was_system
        return None, False

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
            is_system = False
            total_len = 0
            frag_len = 0
            
            if flag == 0xFF:
                frag_len = struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
            else:
                if cursor + 5 > len(data): break
                
                # Check System Bit (Bit 0)
                is_system = (flag & 0x01) != 0
                
                b1, b2, b3 = data[cursor], data[cursor+1], data[cursor+2]
                cursor += 3
                total_len = b1 | (b2 << 8) | (b3 << 16)
                frag_len = struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
                is_start = True
            
            if cursor + frag_len > len(data): break

            payload = data[cursor : cursor + frag_len]
            cursor += frag_len

            completed_msg, was_system = assembler.ingest_chunk(is_start, is_system, total_len, payload, packet_seq)
            
            if completed_msg:
                on_message_reassembled(
                    data=completed_msg, 
                    direction=source_tag, 
                    stream=type_label, 
                    session_id=session_id, 
                    seq=packet_seq,
                    is_system=was_system
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
    global DUMP_VOICE
    
    # --- ARGUMENT PARSING ---
    parser = argparse.ArgumentParser(description="Natural Selection 2 Network Packet Dumper")
    parser.add_argument("filename", help="Path to the .pcapng file")
    parser.add_argument("--dump-voice", action="store_true", help="Enable voice data decoding and saving to WAV")
    
    args = parser.parse_args()
    
    pcap_file = args.filename
    DUMP_VOICE = args.dump_voice

    print(f"Decoding {pcap_file}...")
    if DUMP_VOICE:
        print(f"Voice data will be saved to '{DATA_DIR}/'")
    else:
        print("Voice dump disabled (use --dump-voice to enable).")

    try:
        f = open(pcap_file, 'rb')
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
    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
    except Exception as e:
        print(f"Error: {e}")
        
    # ---- FINAL FLUSH ON PROGRAM EXIT ----
    if DUMP_VOICE:
        try:
            flush_map(initial_game_state.map_load_count, DATA_DIR)
        except Exception as e:
            print(f"[WAV Flush Error] {e}")

        # ---- CLEAN UP SPEEX DECODERS ----
        cleanup()

if __name__ == '__main__':
    main()