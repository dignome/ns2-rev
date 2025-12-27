# ns2-net-dump - Parse pcap network capture and dump data
import dpkt
import socket
import struct
import collections
import os
import zlib
import argparse
import sys
import json
import math
from utils import BinaryReader, BitReader, unpack_field

# avoid string decode errors
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")

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

# Limit consistency file info
MAX_PRINT_FILES = 10
# Limit message dumps
LIST_LIMIT = 225

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
        self.current_client_index = None
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
        
        # Precache
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
        
        self.client_protocol = None
        self.client_build = None
        
        self.server_mode = "None"

# Global Instance
initial_game_state = GameState()

# --- SCHEMA STORAGE ---
# 1. Static Definitions loaded from JSON (Key: Name string)
NETMSG_SCHEMA_DEFS = {} 

# 2. Runtime Schema mapped to current Server IDs (Key: Server ID int)
NETMSG_RUNTIME_SCHEMA = {}

def _netmsg_checksum_u32(chk) -> int | None:
    """
    Accepts:
      - int (already a checksum)
      - str like "C70FB136" or "0xC70FB136"
    Returns unsigned 32-bit int, or None if missing/invalid.
    """
    if chk is None:
        return None
    if isinstance(chk, int):
        return chk & 0xFFFFFFFF

    if isinstance(chk, str):
        s = chk.strip().upper()
        if s.startswith("0X"):
            s = s[2:]
        try:
            return int(s, 16) & 0xFFFFFFFF
        except Exception:
            return None

    return None


def load_netmsg_schema_definitions(json_path: str) -> None:
    """Loads the netmsg schema JSON and indexes it by netmsg name."""
    global NETMSG_SCHEMA_DEFS
    NETMSG_SCHEMA_DEFS = {}

    try:
        with open(json_path, "r") as f:
            raw_data = json.load(f)

        for _, entry in raw_data.items():
            name = entry.get("name")
            if not name:
                continue

            # parse checksum string -> u32 (optional)
            entry["_netmsg_checksum_u32"] = _netmsg_checksum_u32(entry.get("checksum"))
            NETMSG_SCHEMA_DEFS[name] = entry

        print(f"[NetMsgSchema] Loaded {len(NETMSG_SCHEMA_DEFS)} definitions from {json_path}")

    except Exception as e:
        print(f"[NetMsgSchema] Error loading JSON: {e}")

# Call this immediately at script start
load_netmsg_schema_definitions("ns2_netmsg_schema_bad.json")


# ==================================================================================
# PACKET HANDLERS
# ==================================================================================

def handle_client_handshake(data):
    """
    Handles Client -> Server initial handshake (Opcode 0x00).

    A) Spark network layer hello:
       u8    opcode = 0x00
       u8[8] "SPARKNET"
       u32   helloTag (observed: 0x00000009)

    B) Spark engine layer hello:
       u8    opcode = 0x00
       u8[8] "SPARKNET"
       u32   protocolVersion (expected 0x16)
       u32   buildNumber

    We detect which one it is by the first u32 after the signature.
    """
    if not data or data[0] != 0x00:
        return False

    # Need at least opcode + signature + first_u32
    if len(data) < 13:  # (1 + 8 + 4)
        print(f"[Packet 0x00] HANDSHAKE: truncated (len={len(data)}) | {data.hex().upper()}")
        return False

    reader = BinaryReader(data)

    # already checked opcode==0x00, jump to signature
    reader.position(1)
    sig = reader.read_bytes(8)
    if sig != b"SPARKNET":
        try:
            sig_txt = sig.decode("ascii", errors="replace")
        except Exception:
            sig_txt = repr(sig)
        print(f"[Packet 0x00] HANDSHAKE: bad signature '{sig_txt}' | {data.hex().upper()}")
        return False

    first_u32 = reader.read_uint32()

    # -------------------------
    # Variant A: spark network hello (tag == 0x09)
    # -------------------------
    if first_u32 == 0x00000009:
        print(f"\n[Packet 0x00] HANDSHAKE (Client->Server) SPARKNET Hello (net):")
        print(f"  Signature: SPARKNET")
        print(f"  Tag:  0x{first_u32:08X} ({first_u32})")

        # Optional: dump remainder (debug only)
        extra_u32s = []
        while reader.remaining() >= 4:
            extra_u32s.append(reader.read_uint32())
        if extra_u32s:
            print("  ExtraU32s:", " ".join(f"0x{x:08X}({x})" for x in extra_u32s))

        if reader.remaining() > 0:
            tail_bytes = reader.read_bytes(reader.remaining())
            print(f"  TrailingBytes ({len(tail_bytes)}): {tail_bytes.hex().upper()}")

        # IMPORTANT: do NOT set protocol/build for this variant
        return True

    # -------------------------
    # Variant B: spark engine hello
    # first_u32 is protocolVersion
    # -------------------------
    protocol = first_u32

    # Need buildNumber too for the full form
    if len(data) < 17:  # (1 + 8 + 4 + 4)
        print(f"\n[Packet 0x00] HANDSHAKE (Client->Server) SPARKNET Hello (engine):")
        print(f"  Signature: SPARKNET")
        print(f"  Protocol:  0x{protocol:08X} ({protocol})")
        print(f"  [!] Truncated: missing buildNumber (len={len(data)}) | {data.hex().upper()}")
        return False

    build = reader.read_uint32()

    # Only state we persist:
    initial_game_state.client_protocol = protocol
    initial_game_state.client_build = build

    print(f"\n[Packet 0x00] HANDSHAKE (Client->Server) SPARKNET Hello (engine):")
    print(f"  Signature: SPARKNET")
    print(f"  Protocol:  0x{protocol:08X} ({protocol})")
    print(f"  Build:     {build} (0x{build:08X})")

    if protocol != 0x16:
        print("  [!] Protocol mismatch: expected 0x16")

    if reader.remaining() > 0:
        extra_bytes = reader.read_bytes(reader.remaining())
        print(f"  Extra bytes ({len(extra_bytes)}): {extra_bytes.hex().upper()}")

    return True

def handle_client_auth_response(data):
    """
    Handles Client -> Server auth response (Opcode 0x01).

    Expected layout:
      u8     opcode = 0x01
      u8[16] passwordMd5Digest (or auth digest)
      u64    steamId64 (LE)
      u32    ticketLen
      u8[]   ticketBytes (ticketLen)
    """
    if not data or data[0] != 0x01:
        return False

    # Need at least opcode + md5 + steamId + ticketLen
    if len(data) < 29: # (1 + 16 + 8 + 4)
        print(f"[Packet 0x01] CLIENT AUTH: truncated (len={len(data)}) | {data.hex().upper()}")
        return False

    reader = BinaryReader(data)

    # Skip opcode (already checked)
    reader.position(1)

    md5_bytes = reader.read_bytes(16)
    steam_id  = reader.read_uint64()
    ticket_len = reader.read_uint32()

    if reader.remaining() < ticket_len:
        print(f"[Packet 0x01] CLIENT AUTH: ticketLen={ticket_len} but only {reader.remaining()} bytes remain")
        print(f"  md5={md5_bytes.hex().upper()} steamId={steam_id}")
        print(f"  raw={data.hex().upper()}")
        return False

    ticket = reader.read_bytes(ticket_len)

    # Store for later if useful
    initial_game_state.client_auth_md5 = md5_bytes.hex().upper()
    initial_game_state.client_steam_id = steam_id
    initial_game_state.client_auth_ticket_len = ticket_len

    print(f"\n[Packet 0x01] CLIENT AUTH RESPONSE:")
    print(f"  md5:        {initial_game_state.client_auth_md5}")
    print(f"  steamId64:   {steam_id} (0x{steam_id:016X})")
    print(f"  ticketLen:   {ticket_len}")
    print(f"  ticket[0:32]: {ticket[:32].hex().upper()}" + (" ..." if ticket_len > 32 else ""))

    # If there are trailing bytes beyond the ticket, dump them (future-proof)
    if reader.remaining() > 0:
        tail = reader.read_bytes(reader.remaining())
        print(f"  trailing({len(tail)}): {tail.hex().upper()}")

    return True


def handle_client_connected(data):
    """
    Handles Client -> Server 'Client Connected' signal (0x03).
    Layout:
      u8 opcode = 0x03
      u8 voiceEnabled (0/1 typically)
    """
    if len(data) < 2 or data[0] != 0x03:
        return False

    voice_flag = data[1]
    voice_enabled = (voice_flag != 0)

    # Only flush WAVs if voice dumping is enabled
    if DUMP_VOICE and initial_game_state.map_load_count > 0:
        try:
            flush_map(initial_game_state.map_load_count, DATA_DIR)
        except Exception as e:
            print(f"[WAV Flush Error] {e}")

    initial_game_state.map_load_count += 1

    print(
        f"\n[EVENT] Client connected - Global Count: {initial_game_state.map_load_count} | "
        f"VoiceEnabled={voice_enabled} (0x{voice_flag:02X})\n"
    )

    # If there are unexpected extra bytes, show them (future-proof)
    if len(data) > 2:
        extra = data[2:].hex().upper()
        print(f"[ClientConnected 0x03] Extra bytes ({len(data)-2}): {extra}")

    return True

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
        
        if i < LIST_LIMIT:
            print(f"    [{i}] Class Count: {cls_id:<5} | Checksum: {cls_sum:08X}")
    
    if checksum_count > LIST_LIMIT:
        print(f"    ... ({checksum_count - LIST_LIMIT} entries hidden)")

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
        
        if i < LIST_LIMIT:
            print(f"    [{i}] ID: {cls_id:<5} | Name: {cls_name}")

    if name_count > LIST_LIMIT:
        print(f"    ... ({name_count - LIST_LIMIT} entries hidden)")


def parse_netmsg_table(reader: BinaryReader) -> None:
    """
    Parses the server's Network Message Table and builds NETMSG_RUNTIME_SCHEMA.

    Also warns if the JSON netmsg checksum doesn't match the server netmsg checksum.
    """
    print("  --- NetMsg Table ---")
    msg_count = reader.read_uint16()
    print(f"  Network Messages ({msg_count}):")

    initial_game_state.network_messages = []

    global NETMSG_RUNTIME_SCHEMA
    NETMSG_RUNTIME_SCHEMA.clear()

    mapped_count = 0
    mismatch_count = 0
    missing_checksum_count = 0

    for msg_id in range(msg_count):
        msg_name = reader.read_string_null()
        server_chk = reader.read_uint32() & 0xFFFFFFFF

        initial_game_state.network_messages.append({
            "id": msg_id,
            "name": msg_name,
            "checksum": server_chk
        })

        schema = NETMSG_SCHEMA_DEFS.get(msg_name)
        if schema:
            mapped_count += 1
            NETMSG_RUNTIME_SCHEMA[msg_id] = schema

            json_chk = schema.get("_netmsg_checksum_u32")
            if json_chk is None:
                missing_checksum_count += 1
                print(
                    f"    [NetMsgSchema WARN] '{msg_name}' (ID {msg_id}) has no/invalid JSON checksum; "
                    f"server=0x{server_chk:08X}"
                )
            elif json_chk != server_chk:
                mismatch_count += 1
                print(
                    f"    [NetMsgSchema WARN] checksum mismatch for '{msg_name}' (ID {msg_id}): "
                    f"server=0x{server_chk:08X} json=0x{json_chk:08X}"
                )

                # optional: mark it
                schema["_netmsg_checksum_mismatch"] = True
                schema["_netmsg_server_checksum_u32"] = server_chk

        if msg_id < LIST_LIMIT:
            print(f"    [ID {msg_id}] {msg_name:<30} | Checksum: {server_chk:08X}")

    print(f"  ... ({msg_count} total messages)")
    print(f"  [NetMsgSchema] Mapped {mapped_count} IDs to JSON definitions.")
    if mismatch_count or missing_checksum_count:
        print(f"  [NetMsgSchema] WARNINGS: {mismatch_count} mismatches, {missing_checksum_count} missing/invalid checksums.")

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
        
        if i < LIST_LIMIT:
            print(f"    [{i}] {res_val}")
            
    if count > LIST_LIMIT:
        print(f"    ... ({count - LIST_LIMIT} entries hidden)")

def handle_authentication_packet(data):
    """
    Handles Server -> Client 'Authentication' packet (Opcode 0x01).
    Routine: M4::ServerGame::SendAuthenticationPacket
    """
    if not data:
        return False

    reader = BinaryReader(data)

    # 1) Read opcode (expected 0x01)
    opcode = reader.read_uint8()
    if opcode != 0x01:
        return False

    # 2) Password salt (10 bytes)
    SALT_SIZE = 10
    if(reader.remaining() == 0):
        print(f"[Packet 0x01] SERVER READY: (len={len(data)}) | {data.hex().upper()}")
        return True
    elif reader.remaining() < SALT_SIZE + 4:  # need salt + auth_enabled(bool=u32)
        print(f"[Packet 0x01] AUTHENTICATION: truncated (len={len(data)}) | {data.hex().upper()}")
        return False

    salt_bytes = reader.read_bytes(SALT_SIZE)
    initial_game_state.auth_salt = salt_bytes.hex().upper()

    # 3) Authentication enabled flag (WriteBool -> u32)
    initial_game_state.auth_enabled = reader.read_bool()

    print(f"\n[Packet 0x01] AUTHENTICATION:")
    print(f"  Salt: {initial_game_state.auth_salt}")
    print(f"  Auth Enabled: {initial_game_state.auth_enabled}")

    # 4) If enabled, server details follow
    if initial_game_state.auth_enabled:
        # Need port(u32) + addr(u32) + steamid(u64)
        if reader.remaining() < 16: #(4 + 4 + 8):
            print(f"[Packet 0x01] AUTHENTICATION: truncated details (len={len(data)}) | {data.hex().upper()}")
            return False

        initial_game_state.server_port = reader.read_uint32()
        initial_game_state.server_ip = reader.read_ipv4_u32_le()
        initial_game_state.server_steam_id = reader.read_uint64()

        print(f"  Service Port: {initial_game_state.server_port}")
        print(f"  Service Address: {initial_game_state.server_ip}")
        print(f"  Server ID: {initial_game_state.server_steam_id} (0x{initial_game_state.server_steam_id:016X})")

    # Optional: dump trailing bytes (future-proof)
    if reader.remaining() > 0:
        tail = reader.read_bytes(reader.remaining())
        print(f"  trailing({len(tail)}): {tail.hex().upper()}")

    return True

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
        parse_netmsg_table(reader)
        
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

_TWO_PI = 6.283185307179586  # math.tau

def decode_move36(reader: BinaryReader):
    # Move is exactly 36 bytes from current offset
    if reader.remaining() < 36:
        return None

    serial = reader.read_uint32()
    t      = reader.read_float32()
    dt     = reader.read_float32()
    tdt    = reader.read_float32()

    mx, my, mz = reader.read_int8s(3)
    mx_f, my_f, mz_f = mx / 127.0, my / 127.0, mz / 127.0

    pitch_u16 = reader.read_uint16()
    yaw_u16   = reader.read_uint16()

    # u16 is a full-turn fixed-point (0..65535 => 0..360deg)
    pitch_deg = pitch_u16 * 360.0 / 65536.0
    yaw_deg   = yaw_u16   * 360.0 / 65536.0

    pitch_rad = pitch_u16 * _TWO_PI / 65536.0
    yaw_rad   = yaw_u16   * _TWO_PI / 65536.0

    commands = reader.read_uint32()
    hotkey   = reader.read_uint8()

    snapshots_base = reader.read_uint32()
    snapshots_mask = reader.read_uint32()

    snaps = []
    for bit in range(32):
        if snapshots_mask & (1 << bit):
            snaps.append(snapshots_base + bit)
            if len(snaps) >= 10:
                break

    return {
        "serial": serial,
        "time": t,
        "deltaTime": dt,
        "totalDeltaTime": tdt,
        "move": (mx_f, my_f, mz_f),
        "pitch_u16": pitch_u16,
        "yaw_u16": yaw_u16,
        "pitch_deg": pitch_deg,
        "yaw_deg": yaw_deg,
        "pitch_rad": pitch_rad,
        "yaw_rad": yaw_rad,
        "commands": commands,
        "hotkey": hotkey,
        "snapshotsBase": snapshots_base,
        "snapshotsMask": snapshots_mask,
        "snapshotsUsed": len(snaps),
    }


def parse_client_moves(move_bytes: bytes):
    # ProcessMovePacket reads 3 moves.
    reader = BinaryReader(move_bytes)
    moves = []

    for _ in range(3):
        m = decode_move36(reader)
        if m is None:
            break
        moves.append(m)

    trailing = move_bytes[reader.tell():]
    return moves, trailing

def parse_client_voice_and_moves(data):
    """
    Layout (based on ServerWorld::OnClientStatePacket):
      u8    opcode (0x04)
      u32   ackedServerFrame
      u32   clientFrame
      u8    channel
        if channel == 2:
            f32 x, f32 y, f32 z
        if channel == 3:
            f32 x, f32 y, f32 z
            u16 unknown
            u32 entityId
      u16   voiceLen
      u8[]  voiceBytes (voiceLen)
      u8[]  remaining movement bytes (dump as hex)
    """
    # do we have enough data (1 + 4 + 4 + 1 + 2)?
    if len(data) < 12:
        return

    try:
        reader = BinaryReader(data)

        # skip opcode 0x04
        opcode = reader.read_uint8()
        if opcode != 0x04:
            return

        acked_server_frame = reader.read_uint32()
        client_frame       = reader.read_uint32()

        channel = reader.read_uint8()

        # Optional voice spatial header
        pos = None
        entity_id = None

        if channel == 2:
            # 3 floats
            if reader.remaining() < 12:
                return
            x = reader.read_float32()
            y = reader.read_float32()
            z = reader.read_float32()
            pos = (x, y, z)

        elif channel == 3:
            # 3 floats + u16 + u32 entityId
            if reader.remaining() < (12 + 2 + 4):
                return
            x = reader.read_float32()
            y = reader.read_float32()
            z = reader.read_float32()
            _unknown = reader.read_uint16()
            entity_id = reader.read_uint32()
            pos = (x, y, z)

        # voice length
        if reader.remaining() < 2:
            return
        voice_len = reader.read_uint16()

        # sanity: server rejects > 0x3fff, match that behavior
        if voice_len > 0x3FFF:
            print(f"[ClientState 0x04] Client sent too much voice data: {voice_len}")
            # still dump remaining bytes as "movement" from here (best-effort)
            movement_hex = data[reader.tell():].hex().upper()
            print(f"[MOVE04] ackedSrv={acked_server_frame} clientFrm={client_frame} ch={channel} | {movement_hex}")
            return

        if reader.remaining() < voice_len:
            # truncated packet
            return

        voice_bytes = reader.read_bytes(voice_len)

        # Decode Speex immediately using latched client index from SetClientIndex
        if DUMP_VOICE and voice_len > 0:
            client_index = initial_game_state.current_client_index
            if client_index is not None:
                try:
                    pcm = decode_speex_bundle(client_index, channel, voice_bytes)
                    if pcm:
                        append_pcm(initial_game_state.map_load_count, client_index, channel, pcm)
                except Exception:
                    pass

        # Remaining bytes are movement packet data -> dump hex on one line
        move_bytes = data[reader.tell():]
        moves, trailing = parse_client_moves(move_bytes)

        for i, m in enumerate(moves):
            mx, my, mz = m["move"]
            print(
                f"[MOVE] i={i} serial={m['serial']} t={m['time']:.4f} dt={m['deltaTime']:.4f} "
                f"tdt={m['totalDeltaTime']:.4f} move=<{mx:.3f},{my:.3f},{mz:.3f}> "
                f"yaw={m['yaw_deg']:.2f}deg pitch={m['pitch_deg']:.2f}deg "
                f"cmd=0x{m['commands']:08X} hk={m['hotkey']} "
                f"base={m['snapshotsBase']} mask=0x{m['snapshotsMask']:08X}"
                f" snaps_used={m['snapshotsUsed']}"
            )

        if trailing:
            print(f"[MOVE_TRAIL] {trailing.hex().upper()}")

    except Exception:
        # don't crash the main decode loop
        return

def inspect_first_entity(body_bytes, class_names_container=None):
    """
    Parses ONLY the first entity header in the snapshot body.
    Handles the class_names_container being either a List of Dicts (from GameState) 
    or a Dict (if mapped manually).
    """
    if len(body_bytes) < 3:
        # print("    [Entity Parser] Body too short.")
        return

    reader = BinaryReader(body_bytes)
    
    # --- 1. Read Header (3 Bytes) ---
    packed_id = reader.read_uint16()
    class_idx = reader.read_uint8()

    # --- 2. Decode Fields ---
    entity_id = packed_id & 0x3FFF 
    # Increment: It only increments (0 -> 1 -> 2 -> 3 -> 0) after successfully reading an entity header.  Starts at 0 every state snapshot.
    sync_val  = packed_id >> 14
    
    # --- 3. Lookup Name ---
    # If class_name comes back as FF (255) this means the entity id will not be carried over (destroy)
    class_name = f"UNKNOWN_CLASS_{class_idx}"
    
    if class_names_container:
        # Case A: List of Dicts (default GameState structure)
        if isinstance(class_names_container, list):
            for entry in class_names_container:
                if entry.get('class_id') == class_idx:
                    class_name = entry.get('class_name', "UNKNOWN_NAME")
                    break
        # Case B: Dictionary (if optimized later)
        elif isinstance(class_names_container, dict):
            class_name = class_names_container.get(class_idx, class_name)
    else:
        class_name = f"NO_MAPPING ({class_idx})"

    print(f"    [Entity Check] Offset:0x00 | ID:{entity_id:<5} | Sync:{sync_val} | Class:{class_idx} -> '{class_name}'")

def _parse_server_perf(reader: BinaryReader) -> dict:
    """
    On-wire ServerPerformanceData (from decomp readServerPerformanceData):
      f64 timestamp
      i32 score
      i32 quality
      u8  moverate
      u8  interpMs
      u8  tickrate
      u8  sendrate
      u8  maxPlayers
      u16 durationMs
      u8  numPlayers
      u8  updateIntervalMs
      u16 incompleteCount
      u32 numEntitiesUpdated
      u8  timeSpentOnUpdate
      u16 movesProcessed
      u16 timeSpentOnMoves
      u16 timeSpentIdling
      u8  numInterpWarns
      u8  numInterpFails
      u32 bytesSent
      u8  clearingTimeMs10
      u8  clearingTimeMs50
      u8  clearingTimeMs100
    Total = 47 bytes
    """
    return {
        "timestamp": reader.read_float64(),
        "score": reader.read_int32(),
        "quality": reader.read_int32(),

        "moverate": reader.read_uint8(),
        "interpMs": reader.read_uint8(),
        "tickrate": reader.read_uint8(),
        "sendrate": reader.read_uint8(),
        "maxPlayers": reader.read_uint8(),

        "durationMs": reader.read_uint16(),
        "numPlayers": reader.read_uint8(),
        "updateIntervalMs": reader.read_uint8(),

        "incompleteCount": reader.read_uint16(),
        "numEntitiesUpdated": reader.read_uint32(),

        "timeSpentOnUpdate": reader.read_uint8(),
        "movesProcessed": reader.read_uint16(),
        "timeSpentOnMoves": reader.read_uint16(),
        "timeSpentIdling": reader.read_uint16(),

        "numInterpWarns": reader.read_uint8(),
        "numInterpFails": reader.read_uint8(),

        "bytesSent": reader.read_uint32(),

        "clearingTimeMs10": reader.read_uint8(),
        "clearingTimeMs50": reader.read_uint8(),
        "clearingTimeMs100": reader.read_uint8(),
    }


def _f32_from_u32(u: int) -> float:
    return struct.unpack("<f", struct.pack("<I", u & 0xFFFFFFFF))[0]

def _parse_snapshot_header_at(snapshot_bytes: bytes, start_off: int) -> tuple[dict, int]:
    r = BinaryReader(snapshot_bytes)
    r.position(start_off)

    hdr = {}

    hdr["serial"] = r.read_uint32()
    hdr["time"] = _f32_from_u32(r.read_uint32())
    hdr["lastUpdateTime"] = _f32_from_u32(r.read_uint32())
    hdr["maxMoveTime"] = _f32_from_u32(r.read_uint32())
    hdr["injectedMoveTime"] = _f32_from_u32(r.read_uint32())

    hdr["moveSerial"] = r.read_uint32()
    hdr["playerId"] = r.read_uint16()

    # decomp: u32 != 0
    hdr["controlling"] = (r.read_uint32() != 0)

    owned_count = r.read_uint16()
    hdr["ownedByCount"] = owned_count
    if owned_count:
        owned_ids = []
        for _ in range(owned_count):
            owned_ids.append(r.read_uint16())
        hdr["ownedByIds_first64"] = owned_ids[:64]
        if owned_count > 64:
            hdr["ownedByIds_truncated"] = owned_count - 64

    hdr["frameRate"] = _f32_from_u32(r.read_uint32())

    perf_present = (r.read_uint32() != 0)
    hdr["serverPerfPresent"] = perf_present

    if perf_present:
        # compact perf is 47 bytes
        if r.remaining() < 47:
            raise ValueError("perf_present but not enough bytes for perf")
        hdr["serverPerf"] = _parse_server_perf(r)

    # tail (not optional in decomp, but keep your best-effort behavior)
    hdr["serverHadScriptError"] = r.read_uint32()

    # decomp: u32 != 0
    hdr["choked"] = (r.read_uint32() != 0)

    hdr["serverFrame"] = r.read_uint32()
    hdr["oldServerFrame"] = r.read_uint32()

    move_count = r.read_uint16()
    hdr["entityMoveTimeCount"] = move_count
    if move_count:
        mv = []
        for _ in range(move_count):
            eid = r.read_uint16()
            bits = r.read_uint32()
            t = _f32_from_u32(bits)
            if len(mv) < 32:
                mv.append((eid, t))
        hdr["entityMoveTime_first32"] = mv
        if move_count > 32:
            hdr["entityMoveTime_truncated"] = move_count - 32

    return hdr, r.tell()

def _header_plausible(h: dict) -> bool:
    # simple sanity heuristics; tweak as you learn ranges
    fr = h.get("frameRate", 0.0)
    oc = h.get("ownedByCount", -1)
    pid = h.get("playerId", -1)

    if not (0 <= pid <= 4096):
        return False
    if not (0 <= oc <= 2048):
        return False
    if not (fr == fr):  # NaN
        return False
    if not (-1.0 <= fr <= 300.0):
        return False

    # if perf is present, these should be small-ish u8/u16 fields
    if h.get("serverPerfPresent") and "serverPerf" in h:
        p = h["serverPerf"]
        if not (0 <= p.get("tickrate", -1) <= 255): return False
        if not (0 <= p.get("sendrate", -1) <= 255): return False
        if not (0 <= p.get("maxPlayers", -1) <= 255): return False
        if not (0 <= p.get("numPlayers", -1) <= 255): return False

    return True

def try_parse_state_snapshot_header(snapshot_bytes: bytes) -> tuple[dict | None, int]:
    """
    Tries both layouts:
      A) snapshot_bytes starts at serial
      B) snapshot_bytes starts at ReadHeader's leading-return-u32, so serial is at +4
    Returns best parse, else (None, 0).
    """
    # Try A: start at 0
    try:
        hdr0, end0 = _parse_snapshot_header_at(snapshot_bytes, 0)
        ok0 = _header_plausible(hdr0)
    except Exception:
        hdr0, end0, ok0 = None, 0, False

    # Try B: start at 4 (consume leading u32)
    try:
        if len(snapshot_bytes) < 4:
            raise ValueError("too short for leading u32")
        lead = struct.unpack("<I", snapshot_bytes[:4])[0]
        hdr4, end4 = _parse_snapshot_header_at(snapshot_bytes, 4)
        hdr4["readHeader_return_u32"] = lead
        ok4 = _header_plausible(hdr4)
    except Exception:
        hdr4, end4, ok4 = None, 0, False

    # Pick best
    if ok4 and not ok0:
        return hdr4, end4
    if ok0 and not ok4:
        return hdr0, end0
    if ok0 and ok4:
        # prefer the one that consumes more bytes (usually means move list parsed cleanly)
        return (hdr4, end4) if end4 > end0 else (hdr0, end0)

    return None, 0


def parse_voice_and_state(data, session_id):
    """
    Parses Type 5 Packet: Voice Data + Optional State Snapshot.
    
    Logic:
    1. Parse the voice packet headers (ID, Channel, Length) to find where they end.
    2. If --dump-voice is ON: Decode Speex -> WAV.
    3. If --dump-voice is OFF: Skip over voice bytes.
    4. Check for State Snapshot data appearing after the voice payload.
    """
    # cursor = 1  # Skip OpCode (0x05)
    if len(data) < 3: return

    try:
        reader = BinaryReader(data)

        # Skip OpCode (0x05)
        opcode = reader.read_uint8()
        if opcode != 0x05:
            return

        # Read Voice Packet Count (2 bytes)
        voice_count = reader.read_uint16()

        for _ in range(voice_count):
            if reader.remaining() < 3:
                break

            # player_id = struct.unpack_from('<H', data, cursor)[0]
            # channel_id = data[cursor + 2]
            player_id = reader.read_uint16()
            channel_id = reader.read_uint8()

            # --- DETERMINE HEADER FORMAT ---
            header_size = 0
            data_len = 0

            if channel_id == 0x01:  # Standard
                # header_size = 5
                # fields after (player_id:u16, channel:u8):
                #   u16 data_len
                header_size = 5
                if reader.remaining() < (header_size - 3):
                    break
                data_len = reader.read_uint16()

            elif channel_id == 0x02:  # Positional
                # header_size = 17
                # fields after (player_id:u16, channel:u8):
                #   f32 x,y,z (12) + u16 data_len (2)  => 14 bytes
                header_size = 17
                if reader.remaining() < (header_size - 3):
                    break
                # read/skip position floats (we don't use them here)
                reader.read_float32()
                reader.read_float32()
                reader.read_float32()
                data_len = reader.read_uint16()

            elif channel_id == 0x03:  # Positional + Target
                # header_size = 19
                # fields after (player_id:u16, channel:u8):
                #   f32 x,y,z (12) + u16 vc_entity (2) + u16 data_len (2) => 16 bytes
                header_size = 19
                if reader.remaining() < (header_size - 3):
                    break
                # read/skip position floats (we don't use them here)
                reader.read_float32()
                reader.read_float32()
                reader.read_float32()
                # entity either source or target
                vc_entity = reader.read_uint16()
                data_len = reader.read_uint16()

            else:
                # print(f"[Voice Error] Unknown Channel ID: 0x{channel_id:02X}")
                return

            # payload_start = cursor + header_size
            # payload_end = payload_start + data_len
            if reader.remaining() < data_len:
                break

            # --- CONDITIONAL DECODING ---
            if DUMP_VOICE:
                speex_data = reader.read_bytes(data_len)
                try:
                    pcm = decode_speex_bundle(player_id, channel_id, speex_data)
                    if pcm:
                        append_pcm(initial_game_state.map_load_count, player_id, channel_id, pcm)
                except Exception:
                    pass
            else:
                # If --dump-voice is OFF: Skip over voice bytes.
                reader.skip(data_len)

            # Always advance cursor so we can find the Snapshot
            # (reader offset is already advanced by read_bytes/skip)

        # 3. State Snapshot
        # After voice loop, next 4 bytes are ALWAYS Snapshot Length
        if reader.remaining() >= 4:
            snapshot_len = reader.read_uint32()
            actual_len = min(snapshot_len, reader.remaining())

            if actual_len > 0:
                snap_bytes = reader.read_bytes(actual_len)
                
                try:
                    # Parse header at offset 0 of the isolated snapshot bytes
                    hdr, hdr_end_off = _parse_snapshot_header_at(snap_bytes, 0)
                    
                    print(f"[Snapshot] Len: {snapshot_len} | Serial: {hdr.get('serial')} | Time: {hdr.get('time', 0.0):.3f}")
                    
                    print(
                        f"    moveSerial={hdr.get('moveSerial')} "
                        f"playerId={hdr.get('playerId')} controlling={hdr.get('controlling')} "
                        f"lastUpd={hdr.get('lastUpdateTime', 0.0):.3f} "
                        f"frameRate={hdr.get('frameRate', 0.0):.3f}"
                    )
                    
                    print(
                        f"    ownedCount={hdr.get('ownedByCount')} "
                        f"perf={hdr.get('serverPerfPresent')} scriptError={hdr.get('serverHadScriptError')} "
                        f"choked={hdr.get('choked')} "
                        f"serverFrame={hdr.get('serverFrame')} oldFrame={hdr.get('oldServerFrame')}"
                    )

                    # Print Perf if present
                    if hdr.get("serverPerfPresent") and "serverPerf" in hdr:
                        p = hdr["serverPerf"]
                        print(
                            f"    [Perf] Score:{p.get('score')} Tick:{p.get('tickrate')} "
                            f"Send:{p.get('sendrate')} Players:{p.get('numPlayers')}/{p.get('maxPlayers')} "
                            f"Qual:{p.get('quality')} EntsUpd:{p.get('numEntitiesUpdated')}"
                        )
                    
                    # Dump Body Hex
                    body_bytes = snap_bytes[hdr_end_off:]
                    body_hex = body_bytes.hex().upper()
                    print(f"    [Body Hex] {body_hex[:64]}..." if len(body_hex) > 64 else f"    [Body Hex] {body_hex}")
                    
                    # [INSERTION] Parse First Entity Header
                    # We pass the raw list from GameState; the helper function now handles the iteration.
                    class_list = getattr(initial_game_state, 'net_class_names', None)
                    inspect_first_entity(body_bytes, class_list)

                except Exception as e:
                    print(f"[Snapshot] Error parsing header: {e}")

                except Exception as e:
                    print(f"[Snapshot] Error parsing header: {e}")

    except Exception:
        # match old behavior: don't crash main decode loop
        pass


def handle_network_message(data):
    """
    Handles Network Message  (Opcode 0x06).
    Uses NETMSG_RUNTIME_SCHEMA to decode specific fields.
    """
    try:
        reader = BitReader(data)
        
        # 1. Header
        opcode = reader.read_bits(8)
        msg_index = reader.read_bits(16)
        timestamp = reader.read_float()
        
        # 2. Lookup Name and Schema
        msg_name = f"Unknown({msg_index})"
        schema = NETMSG_RUNTIME_SCHEMA.get(msg_index)
        
        # Fallback name lookup if not in schema but in game state
        if not schema:
            for m in initial_game_state.network_messages:
                if m['id'] == msg_index:
                    msg_name = m['name']
                    break
        else:
            msg_name = schema['name']
        
        print(f"\n[Packet 0x06] NETWORK MESSAGE:")
        print(f"  Message: {msg_name} (ID: {msg_index})")
        print(f"  Timestamp: {timestamp:.4f}")
        
        # 3. Payload Parsing
        if schema:
            print("  -- Payload --")
            fields = schema.get('fields', [])
            
            for field in fields:
                field_name = field['name']
                try:
                    val = unpack_field(reader, field)
                    
                    if msg_name == "SetClientIndex" and field_name == "clientIndex":
                        initial_game_state.current_client_index = int(val)
                    
                    # Format output nicely
                    if isinstance(val, float):
                        print(f"    {field_name}: {val:.4f}")
                    elif isinstance(val, dict) and 'x' in val: # Vector
                        print(f"    {field_name}: <{val['x']:.2f}, {val['y']:.2f}, {val['z']:.2f}>")
                    else:
                        print(f"    {field_name}: {val}")
                        
                except Exception as e:
                    print(f"    {field_name}: [Error unpacking] {e}")
                    break
        else:
            print("  [!] No Schema Definition found for this ID.")

        # 4. Debug: Print remaining bits (Garbage/Padding check)
        total_bits = len(data) * 8
        current_bit_pos = (reader.byte_offset * 8) + reader.bit_offset
        remaining_bits = total_bits - current_bit_pos
        
        if remaining_bits > 0 and remaining_bits < 64: # Only print if small garbage remains
             # If we parsed correctly, this should just be the byte alignment padding
             pass
        elif remaining_bits > 0:
             # If we didn't have a schema, dump the hex
             raw_payload = data[reader.byte_offset:]
             print(f"  Unparsed Payload ({remaining_bits} bits): {raw_payload.hex().upper()}")

    except Exception as e:
        print(f"[Packet 0x06] Critical Error: {e}")
        import traceback
        traceback.print_exc()

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

    # --- ADDED: Raw Hex Dump ---
    # format: [RAW] SERVER RELIABLE Seq:1 Op:0x06 | <HEX_DATA>
    op_debug = data[0]
    print(f"[RAW] {direction:<6} {stream:<10} Seq:{seq:<3} Op:0x{op_debug:02X} | {data.hex().upper()}")
    # ---------------------------

    op_code = data[0]

    # (Server->Client) --- SERVER RELIABLE PACKETS ---
    if direction == "SERVER" and stream == "RELIABLE":
        
        # 0x06: Network Message (either script or internal)
        if op_code == 0x06:
            handle_network_message(data)
        elif op_code == 0x02: # Opcode 0x02: Collision Handler
            if is_system:
                # System Packet 0x02 -> Disconnect
                handle_disconnect_packet(data)
            else:
                # Normal Packet 0x02 -> Connecting
                handle_connecting_packet(data)

        # 0x01: Authentication
        elif op_code == 0x01:
            handle_authentication_packet(data)
        
        # 0x07: OnMode (Mode Change)
        elif op_code == 0x07:
            parse_mode_packet(data)
    
    # (Server->Client) --- SERVER UNRELIABLE PACKETS ---
    if direction == "SERVER" and stream == "UNRELIABLE":
        # 0x06: Network Message (either script or internal)
        if op_code == 0x06:
            handle_network_message(data)
        
        # Voice / State Packet
        elif op_code == 0x05:
            parse_voice_and_state(data, session_id)
    
    # (Client->Server) --- CLIENT RELIABLE PACKETS ---
    if direction == "CLIENT" and stream == "RELIABLE":
        # Network Message
        if op_code == 0x06:
            handle_network_message(data)
        
        # Client Initiate Connection
        elif op_code == 0x00:
            handle_client_handshake(data)
            
        elif op_code == 0x01:
            handle_client_auth_response(data)
        
        # Client Connected - Map Counter
        elif op_code == 0x03:
            handle_client_connected(data)
 
    # (Client->Server) Client Voice / Moves
    if direction == "CLIENT" and stream == "UNRELIABLE" and op_code == 0x04:
        parse_client_voice_and_moves(data)


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