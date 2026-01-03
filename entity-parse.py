# entity-parse.py - Proof of concept snapshot state reader for NS2
# Builds an entity state frame by frame.
import json
import base64
import struct
import copy
import sys

# avoid string decode errors
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")

# ==============================================================================
# CONSTANTS
# ==============================================================================
NET_TYPE_ANGLE    = 0x0
NET_TYPE_ANGLES   = 0x1
NET_TYPE_BOOL     = 0x2
NET_TYPE_FIXED    = 0x3
NET_TYPE_INTEGER  = 0x4
NET_TYPE_POSITION = 0x5
NET_TYPE_STRING   = 0x6
NET_TYPE_VECTOR   = 0x7
NET_TYPE_FLOAT    = 0x8
NET_TYPE_TIME     = 0x9

# ==============================================================================
# BIT READER
# ==============================================================================
class BitReader:
    def __init__(self, data):
        self.data = data
        self.total_bits = len(data) * 8
        self.current_bit_index = 0

    def remaining_bits(self):
        return self.total_bits - self.current_bit_index

    def tell(self):
        return self.current_bit_index

    def seek(self, bit_pos):
        self.current_bit_index = bit_pos

    def align_to_byte(self):
        remainder = self.current_bit_index % 8
        if remainder != 0:
            self.current_bit_index += (8 - remainder)

    def read_bool(self):
        return self.read_bits(1) == 1

    def read_bits(self, num_bits):
        if num_bits == 0: return 0
        val = 0
        for i in range(num_bits):
            byte_idx = self.current_bit_index // 8
            bit_idx = self.current_bit_index % 8
            if byte_idx >= len(self.data): return val
            if (self.data[byte_idx] >> bit_idx) & 1:
                val |= (1 << i)
            self.current_bit_index += 1
        return val

    def read_float(self):
        int_val = self.read_bits(32)
        return struct.unpack('<f', struct.pack('<I', int_val))[0]

    def read_uint32_aligned(self):
        self.align_to_byte()
        byte_idx = self.current_bit_index // 8
        if byte_idx + 4 > len(self.data): return 0
        val = struct.unpack('<I', self.data[byte_idx:byte_idx+4])[0]
        self.current_bit_index += 32
        return val

    def read_uint16_aligned(self):
        self.align_to_byte()
        byte_idx = self.current_bit_index // 8
        if byte_idx + 2 > len(self.data): return 0
        val = struct.unpack('<H', self.data[byte_idx:byte_idx+2])[0]
        self.current_bit_index += 16
        return val
        
    def skip_bytes(self, num_bytes):
        self.align_to_byte()
        self.current_bit_index += (num_bytes * 8)

    def read_string(self, num_bits):
        if num_bits <= 0: return ""
        if num_bits > 131072: return "<MASSIVE_STRING_ERR>"

        num_bytes = num_bits // 8
        remaining_bits = num_bits % 8
        
        raw_bytes = bytearray()
        for _ in range(num_bytes):
            raw_bytes.append(self.read_bits(8))

        if remaining_bits > 0:
            self.read_bits(remaining_bits)

        try:
            full_str = raw_bytes.decode('iso-8859-1')
            return full_str.split('\x00')[0]
        except:
            return "<decode_err>"

    def read_bytes_aligned(self, num_bytes: int) -> bytes:
        self.align_to_byte()
        byte_idx = self.current_bit_index // 8
        end = byte_idx + num_bytes
        if byte_idx >= len(self.data):
            return b""
        if end > len(self.data):
            b = self.data[byte_idx:]
            self.current_bit_index = len(self.data) * 8
            return b
        b = self.data[byte_idx:end]
        self.current_bit_index += num_bytes * 8
        return b

    def read_uint8_aligned(self) -> int:
        b = self.read_bytes_aligned(1)
        return b[0] if len(b) == 1 else 0

    def read_int32_aligned(self) -> int:
        b = self.read_bytes_aligned(4)
        if len(b) < 4:
            b = b.ljust(4, b"\x00")
        return struct.unpack("<i", b)[0]

    def read_float32_aligned(self) -> float:
        b = self.read_bytes_aligned(4)
        if len(b) < 4:
            b = b.ljust(4, b"\x00")
        return struct.unpack("<f", b)[0]

    def read_float64_aligned(self) -> float:
        b = self.read_bytes_aligned(8)
        if len(b) < 8:
            b = b.ljust(8, b"\x00")
        return struct.unpack("<d", b)[0]


# ==============================================================================
# FIELD UNPACKER
# ==============================================================================
def unpack_field(reader, field, verbose=False):
    f_type = field.get('type')
    f_name = field.get('name', '???')
    
    bit_start = reader.tell()

    if verbose:
        print(f"      [Field] {f_name} (Type {f_type}) @ Bit {bit_start}", end='')

    if f_type == NET_TYPE_BOOL:
        val = reader.read_bool()
        if verbose:
            print(f" -> consumed {reader.tell() - bit_start} bits, val={val}")
        return val

    if f_type == NET_TYPE_STRING:
        max_bits = field.get('numBits', 0)
        val = reader.read_string(max_bits)
        if verbose:
            print(f" -> consumed {reader.tell() - bit_start} bits, val='{val[:20]}...'")
        return val

    def u32_to_f32(u: int) -> float:
        return struct.unpack("<f", struct.pack("<I", u & 0xFFFFFFFF))[0]

    def read_component(step_info):
        bits = int(step_info.get('bits', 0))
        min_raw = step_info.get('min_raw', 0) or 0
        step_val = step_info.get('stepValue', 0)
        range_raw = step_info.get('range_raw', 0) or 0
        
        if verbose:
            print(f" [read_component: bits={bits}, step={step_val}, min={min_raw}]", end='')

        if bits == 32 and step_val == 0 and min_raw == 0 and range_raw == 0:
            raw_u32 = reader.read_bits(32)
            return u32_to_f32(raw_u32)

        raw_val = reader.read_bits(bits)
        
        if step_val is not None and step_val != 0:
            return (raw_val + min_raw) * step_val
        else:
            return raw_val + min_raw
        
    if f_type in [NET_TYPE_VECTOR, NET_TYPE_POSITION, NET_TYPE_ANGLES]:
        comps = field.get('components', [])
        if len(comps) >= 3:
            x = read_component(comps[0])
            y = read_component(comps[1])
            z = read_component(comps[2])
            val = {'x': float(x), 'y': float(y), 'z': float(z)}
        else:
            x = reader.read_float()
            y = reader.read_float()
            z = reader.read_float()
            val = {'x': x, 'y': y, 'z': z}
        
        if verbose:
            print(f" -> consumed {reader.tell() - bit_start} bits, val=({val['x']:.2f}, {val['y']:.2f}, {val['z']:.2f})")
        return val

    comps = field.get('components', [])
    if comps:
        val = read_component(comps[0])
        if f_type == NET_TYPE_INTEGER:
            val = int(val)
        else:
            val = float(val)
        
        if verbose:
            print(f" -> consumed {reader.tell() - bit_start} bits, val={val}")
        return val

    max_bits = field.get('numBits', 32)
    
    if f_type == NET_TYPE_FLOAT:
        if max_bits == 32:
            val = reader.read_float()
        else:
            val = reader.read_bits(max_bits)
        if verbose:
            print(f" -> consumed {reader.tell() - bit_start} bits, val={val}")
        return val
    
    if f_type == NET_TYPE_INTEGER:
        val = reader.read_bits(max_bits)
        if verbose:
            print(f" -> consumed {reader.tell() - bit_start} bits, val={val}")
        return val

    # Default case for unknown types (including TIME which is type 9)
    val = reader.read_bits(max_bits)
    if verbose:
        print(f" -> consumed {reader.tell() - bit_start} bits, val={val}")
    return val

# ==============================================================================
# ENTITY READERS
# ==============================================================================
def _parse_server_perf(reader: BitReader) -> dict:
    # 47 bytes total
    return {
        "timestamp": reader.read_float64_aligned(),
        "score": reader.read_int32_aligned(),
        "quality": reader.read_int32_aligned(),

        "moverate": reader.read_uint8_aligned(),
        "interpMs": reader.read_uint8_aligned(),
        "tickrate": reader.read_uint8_aligned(),
        "sendrate": reader.read_uint8_aligned(),
        "maxPlayers": reader.read_uint8_aligned(),

        "durationMs": reader.read_uint16_aligned(),
        "numPlayers": reader.read_uint8_aligned(),
        "updateIntervalMs": reader.read_uint8_aligned(),

        "incompleteCount": reader.read_uint16_aligned(),
        "numEntitiesUpdated": reader.read_uint32_aligned(),

        "timeSpentOnUpdate": reader.read_uint8_aligned(),
        "movesProcessed": reader.read_uint16_aligned(),
        "timeSpentOnMoves": reader.read_uint16_aligned(),
        "timeSpentIdling": reader.read_uint16_aligned(),

        "numInterpWarns": reader.read_uint8_aligned(),
        "numInterpFails": reader.read_uint8_aligned(),

        "bytesSent": reader.read_uint32_aligned(),

        "clearingTimeMs10": reader.read_uint8_aligned(),
        "clearingTimeMs50": reader.read_uint8_aligned(),
        "clearingTimeMs100": reader.read_uint8_aligned(),
    }

MAX_ENTS = 0xFFE

def parse_header(reader: BitReader):
    info = {}

    reader.align_to_byte()
    snap_len = reader.read_uint32_aligned()
    info["snapshot_len"] = int(snap_len)

    declared_total_bytes = 4 + int(snap_len)
    usable_bytes = min(declared_total_bytes, len(reader.data))
    reader.total_bits = usable_bytes * 8

    info["serial"] = reader.read_uint32_aligned()
    info["time"] = reader.read_float32_aligned()
    info["lastUpdateTime"] = reader.read_float32_aligned()
    info["maxMoveTime"] = reader.read_float32_aligned()
    info["injectedMoveTime"] = reader.read_float32_aligned()

    info["moveSerial"] = reader.read_uint32_aligned()
    info["playerId"] = reader.read_uint16_aligned()

    info["controlling"] = (reader.read_uint32_aligned() != 0)

    # ---- ownedByPlayer ----
    owned = bytearray(MAX_ENTS)  # 0/1
    owned_count = reader.read_uint16_aligned()
    info["ownedByCount"] = int(owned_count)

    owned_first = []
    for i in range(int(owned_count)):
        oid = int(reader.read_uint16_aligned())
        if 0 <= oid < MAX_ENTS:
            owned[oid] = 1
        if len(owned_first) < 64:
            owned_first.append(oid)

    info["ownedByIds_first64"] = owned_first
    if owned_count > 64:
        info["ownedByIds_truncated"] = int(owned_count - 64)

    info["frameRate"] = reader.read_float32_aligned()

    perf_present = (reader.read_uint32_aligned() != 0)
    info["serverPerfPresent"] = perf_present
    if perf_present:
        bytes_left = (reader.total_bits - reader.tell()) // 8
        if bytes_left >= 47:
            info["serverPerf"] = _parse_server_perf(reader)
        else:
            info["serverPerf_truncated"] = True
            reader.skip_bytes(bytes_left)

    info["serverHadScriptError"] = reader.read_uint32_aligned()
    info["choked"] = (reader.read_uint32_aligned() != 0)

    info["serverFrame"] = reader.read_uint32_aligned()
    info["oldServerFrame"] = reader.read_uint32_aligned()

    move_count = reader.read_uint16_aligned()
    info["entityMoveTimeCount"] = int(move_count)
    for _ in range(int(move_count)):
        _ = reader.read_uint16_aligned()
        _ = reader.read_float32_aligned()

    info["entityStreamStartBit"] = reader.tell()
    info["usableBytes"] = usable_bytes
    return info, owned

def print_snapshot_header(header: dict, payload_len: int, trace: bool = False):
    snap_len = int(header.get("snapshot_len", 0))
    declared_total = 4 + snap_len
    usable = int(header.get("usableBytes", 0))

    # Always print a one-liner summary
    print(
        f"[SNAP] sf={header.get('serverFrame')} old={header.get('oldServerFrame')} "
        f"serial={header.get('serial')} pid={header.get('playerId')} "
        f"fps={float(header.get('frameRate', 0.0)):.2f} "
        f"ctrl={header.get('controlling')} choked={header.get('choked')} "
        f"perf={header.get('serverPerfPresent')} "
        f"len={snap_len} buf={payload_len} expect={declared_total} usable={usable}"
    )

    # Mismatch warnings (super useful)
    if payload_len < declared_total:
        print(f"  [WARN] SNAPSHOT TRUNCATED: buffer={payload_len} < expected={declared_total} (missing {declared_total - payload_len} bytes)")
    elif payload_len > declared_total:
        print(f"  [INFO] SNAPSHOT HAS TRAILING BYTES: buffer={payload_len} > expected={declared_total} (extra {payload_len - declared_total} bytes ignored)")

    # If perf present, print a compact perf line
    if header.get("serverPerfPresent") and isinstance(header.get("serverPerf"), dict):
        p = header["serverPerf"]
        print(
            f"  [PERF] score={p.get('score')} quality={p.get('quality')} "
            f"tick={p.get('tickrate')} send={p.get('sendrate')} move={p.get('moverate')} "
            f"players={p.get('numPlayers')}/{p.get('maxPlayers')} "
            f"durMs={p.get('durationMs')} bytesSent={p.get('bytesSent')} "
            f"entitiesUpd={p.get('numEntitiesUpdated')} incomplete={p.get('incompleteCount')}"
        )

    # Optional: if you want more detail only when tracing
    if trace:
        print(
            f"  [HDR] time={header.get('time'):.3f} lastUpdate={header.get('lastUpdateTime'):.3f} "
            f"maxMove={header.get('maxMoveTime'):.3f} injectedMove={header.get('injectedMoveTime'):.3f} "
            f"moveSerial={header.get('moveSerial')} scriptErr={header.get('serverHadScriptError')} "
            f"entityMoveTimes={header.get('entityMoveTimeCount')}"
        )


def read_baseline(reader, class_table, class_id, is_optimized, verbose=False):
    schema = class_table.get(class_id)
    new_ent = {'classId': class_id, 'fields': {}}
    if schema:
        for field in schema['fields']:
            if not is_optimized:
                flags = field.get('flags', 0)
                if (flags & 4) != 0: continue
            
            val = unpack_field(reader, field, verbose)
            new_ent['fields'][field['name']] = val
    return new_ent

def read_field_diff(reader, field, base_val, verbose=False):
    """Read a field value in diff/update mode (handles delta compression)"""
    
    f_name = field.get('name', '???')
    packer = field.get('packer', {})
    num_type_bits = int(packer.get('numTypeBits', 0) or 0)
    num_types = int(packer.get('numTypes', 0) or 0)
    deltas = packer.get('deltas', [])
    
    # If no packer, read full value
    if num_type_bits == 0 or num_types == 0 or not deltas:
        return unpack_field(reader, field, verbose)
    
    # CRITICAL FIX: Check if we have a base value BEFORE reading selector
    # If no base, we must read as full value (which includes its own encoding)
    if base_val is None:
        if verbose:
            print(f"        [Delta] {f_name}: No base value, must read as FULL (no selector)")
        return unpack_field(reader, field, verbose)
    
    # Read delta selector
    bit_before = reader.tell()
    selector = reader.read_bits(num_type_bits)
    
    if verbose:
        print(f"        [Delta] {f_name}: selector={selector} (read {num_type_bits} bits @ {bit_before})")
        print(f"                numTypes={num_types}, len(deltas)={len(deltas)}")
    
    # selector == num_types means "full value" (escape code)
    if selector == num_types:
        if verbose:
            print(f"                -> FULL VALUE (escape)")
        return unpack_field(reader, field, verbose)
    
    # selector >= num_types is invalid
    if selector >= len(deltas):
        print(f"  [ERROR] Invalid delta selector {selector} for field {f_name}")
        print(f"          numTypeBits={num_type_bits}, numTypes={num_types}, len(deltas)={len(deltas)}")
        return base_val
    
    # Get delta configuration
    delta_config = deltas[selector]
    bits_spec = delta_config.get('bits')
    
    if verbose:
        print(f"                -> Delta config[{selector}]: bits={bits_spec}")
    
    f_type = field.get('type')
    comps = field.get('components', [])
    
    # Helper: read centered delta
    def read_delta_centered(bits):
        if bits <= 0:
            return 0
        bit_start = reader.tell()
        raw = reader.read_bits(bits)
        max_val = (1 << bits) - 1
        centered = raw - (max_val >> 1)
        if verbose:
            print(f"                   Read {bits} bits @ {bit_start}: raw={raw} -> centered={centered}")
        return centered
    
    # Vector delta: bits = [bx, by, bz]
    if isinstance(bits_spec, list) and len(bits_spec) >= 3 and len(comps) >= 3:
        if not isinstance(base_val, dict):
            if verbose:
                print(f"                -> Base not a vector, reading full")
            return unpack_field(reader, field, verbose)
        
        def to_raw(val, comp):
            step = comp.get('stepValue', 0) or 0
            min_raw = comp.get('min_raw', 0) or 0
            if step:
                return int(round(float(val) / float(step) - float(min_raw)))
            return int(round(float(val) - float(min_raw)))
        
        def from_raw(raw, comp):
            step = comp.get('stepValue', 0) or 0
            min_raw = comp.get('min_raw', 0) or 0
            if step:
                return float((raw + min_raw) * step)
            return float(raw + min_raw)
        
        bx, by, bz = int(bits_spec[0] or 0), int(bits_spec[1] or 0), int(bits_spec[2] or 0)
        
        if verbose:
            print(f"                -> Vector delta: bx={bx}, by={by}, bz={bz}")
        
        base_rx = to_raw(base_val.get('x', 0), comps[0])
        base_ry = to_raw(base_val.get('y', 0), comps[1])
        base_rz = to_raw(base_val.get('z', 0), comps[2])
        
        if verbose:
            print(f"                   Base raw: ({base_rx}, {base_ry}, {base_rz})")
        
        dx = read_delta_centered(bx) if bx > 0 else 0
        dy = read_delta_centered(by) if by > 0 else 0
        dz = read_delta_centered(bz) if bz > 0 else 0
        
        new_rx = base_rx + dx
        new_ry = base_ry + dy
        new_rz = base_rz + dz
        
        result = {
            'x': from_raw(new_rx, comps[0]),
            'y': from_raw(new_ry, comps[1]),
            'z': from_raw(new_rz, comps[2])
        }
        
        if verbose:
            print(f"                   New raw: ({new_rx}, {new_ry}, {new_rz})")
            print(f"                   Result: ({result['x']:.3f}, {result['y']:.3f}, {result['z']:.3f})")
        
        return result
    
    # Scalar delta: bits = int or [int]
    if isinstance(bits_spec, list) and len(bits_spec) == 1:
        bits_spec = int(bits_spec[0] or 0)
    
    if isinstance(bits_spec, int):
        bits = int(bits_spec)
        if bits <= 0:
            if verbose:
                print(f"                -> 0-bit delta, unchanged")
            return base_val
        
        delta = read_delta_centered(bits)
        
        # Apply delta in quantized space if component exists
        if comps:
            comp = comps[0]
            step = comp.get('stepValue', 0) or 0
            min_raw = comp.get('min_raw', 0) or 0
            
            if step:
                base_raw = int(round(float(base_val) / float(step) - float(min_raw)))
                new_raw = base_raw + delta
                result = float((new_raw + min_raw) * step)
                if verbose:
                    print(f"                   Base: {base_val} (raw={base_raw}), delta={delta}")
                    print(f"                   New: {result} (raw={new_raw})")
                return result
            else:
                base_raw = int(round(float(base_val) - float(min_raw)))
                new_raw = base_raw + delta
                result = float(new_raw + min_raw)
                if verbose:
                    print(f"                   Base: {base_val} (raw={base_raw}), delta={delta}")
                    print(f"                   New: {result} (raw={new_raw})")
                return result
        
        # No quantization, just add delta
        try:
            result = (base_val or 0) + delta
            if verbose:
                print(f"                   Base: {base_val}, delta={delta}, new: {result}")
            return result
        except:
            return base_val
    
    # Unknown delta format, read full value
    if verbose:
        print(f"                -> Unknown delta format, reading full")
    return unpack_field(reader, field, verbose)

def read_diff(reader, class_table, base, class_id, is_dense, verbose=False):
    new_ent = copy.deepcopy(base)
    schema = class_table.get(class_id)
    if not schema: return new_ent
    
    fields = schema['fields']
    num_fields = len(fields)
    indices = []

    if is_dense:
        if verbose: print("    [Mode] DENSE (Bitmask)")
        
        # The mask is written as a continuous stream of 'num_fields' bits.
        # We must read exactly that many bits. 
        mask_bits = reader.read_bits(num_fields)
        
        if verbose:
            print(f"      Mask bits: {bin(mask_bits)}")

        # Iterate bits to find which fields changed (LSB = index 0)
        for i in range(num_fields):
            if (mask_bits >> i) & 1:
                indices.append(i)
        # --- FIX END ---
        
        if verbose:
            print(f"      Changed field indices ({len(indices)} total): {indices[:20]}{'...' if len(indices) > 20 else ''}")
                
    else:
        if verbose: print("    [Mode] SPARSE (Indices)")
        max_idx = num_fields - 1
        bits_per_idx = max(1, max_idx.bit_length())
        count = reader.read_bits(bits_per_idx)
        if verbose: print(f"    [Sparse] Count: {count}, bits_per_idx: {bits_per_idx}")
        for _ in range(count):
            idx = reader.read_bits(bits_per_idx)
            if idx >= num_fields:
                print(f"  [ERROR] Field index {idx} out of bounds (max: {max_idx})")
                break
            indices.append(idx)

    # Unpack changed fields using delta-aware reading
    for i in indices:
        if i < num_fields:
            field = fields[i]
            base_val = new_ent['fields'].get(field['name'])
            val = read_field_diff(reader, field, base_val, verbose)
            new_ent['fields'][field['name']] = val

    return new_ent
    
# ==============================================================================
# MAIN
# ==============================================================================

def parse_trace_frames(s: str) -> set[int]:
    s = (s or "").strip()
    if not s:
        return set()

    out = set()
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            a = int(a.strip())
            b = int(b.strip())
            lo, hi = (a, b) if a <= b else (b, a)
            out.update(range(lo, hi + 1))
        else:
            out.add(int(p))
    return out

def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--class_table", default="snapshot-classtable.json")
    ap.add_argument("--snapshots", default="snapshots.json")
    ap.add_argument("--game", type=int, default=None, help="only parse snapshots data matching this counter value")
    ap.add_argument("--trace_frames", default="", help="comma-separated frame numbers to trace (e.g. 21,22)")
    args = ap.parse_args()

    # --------------------------------------------------------------------------
    # Load schema
    # --------------------------------------------------------------------------
    try:
        with open(args.class_table, "r") as f:
            raw = json.load(f)

        # Your class table sometimes comes wrapped; handle both shapes:
        # 1) { "9": { "name":..., "fields":[...] }, ... }
        # 2) { "0": { "9": {...}, ... } } or similar
        if isinstance(raw, dict) and raw:
            first_key = next(iter(raw.keys()))
            if isinstance(raw[first_key], dict) and "fields" in raw[first_key]:
                class_table = raw
            else:
                # unwrap one level
                class_table = raw[first_key]
        else:
            raise RuntimeError("Bad class table JSON shape")
    except Exception as e:
        print(f"Error loading class table: {e}")
        return

    # --------------------------------------------------------------------------
    # Load snapshots
    # --------------------------------------------------------------------------
    try:
        with open(args.snapshots, "r") as f:
            snaps_raw = json.load(f)

        snaps = []
        if isinstance(snaps_raw, dict):
            for g in snaps_raw.values():
                if isinstance(g, list):
                    snaps.extend(g)
        elif isinstance(snaps_raw, list):
            snaps = snaps_raw

        # Filter by game counter if specified
        if args.game is not None:
            snaps = [s for s in snaps if s.get("counter") == args.game]
            print(f"[*] Filtered for Game (counter): {args.game}. Found {len(snaps)} snapshots.")
        # ---------------------------

        snaps.sort(key=lambda x: x.get("pcap_ts", 0))
    except Exception as e:
        print(f"Error loading snapshots: {e}")
        return

    # --------------------------------------------------------------------------
    # Config / state
    # --------------------------------------------------------------------------
    ID_MASK = 0x0FFF
    SYNC_SHIFT = 12
    SYNC_MASK = 0x0F

    trace_set = set()
    try:
        trace_set = parse_trace_frames(args.trace_frames)
    except:
        trace_set = (0)

    world_hist = {}
    MAX_HIST = 64
    baseline_found = False
    current_session_id = None  # from snapshots.json; change => new world

    print(f"Processing {len(snaps)} snapshots...")

    # --------------------------------------------------------------------------
    # Process snapshots in time order
    # --------------------------------------------------------------------------
    for snap in snaps:
        # Session handling:
        # If session_id changes, treat it as a brand-new world and flush history.
        sess = snap.get("session_id", None)
        if current_session_id is None:
            current_session_id = sess
        elif sess is not None and current_session_id is not None and sess != current_session_id:
            print(f"\n[SESSION] session_id changed {current_session_id} -> {sess}; flushing world state/history\n")
            current_session_id = sess
            world_hist.clear()
            baseline_found = False
        
        # decode snapshot payload (base64)
        try:
            payload = base64.b64decode(snap["bytes_b64"])
        except Exception:
            continue

        reader = BitReader(payload)

        # parse fixed header (aligned / bytewise stuff)
        try:
            header, owned_cur = parse_header(reader)
        except Exception:
            continue

        frame = int(header.get("serverFrame", 0))
        old_frame = int(header.get("oldServerFrame", 0))
        
        # ------------------------------------------------------------------
        # RECONNECT / BASELINE RESTART:
        # If we suddenly see a new baseline sequence starting at (sf=1, old=0)
        # while we already have history, flush the world.
        # ------------------------------------------------------------------
        if frame == 1 and old_frame == 0 and world_hist:
            print(f"\n[RESET] baseline restart detected (sf=1 old=0); flushing world state/history\n")
            world_hist.clear()
            baseline_found = False

        # Wait for a baseline snapshot (oldServerFrame == 0)
        if not baseline_found:
            if old_frame == 0:
                print(f"[*] BASELINE FOUND: Frame {frame}")
                baseline_found = True
            else:
                continue

        # old world = referenced frame (oldServerFrame)
        old_state = world_hist.get(old_frame) if old_frame > 0 else None
        old_ents = old_state["ents"] if old_state else {}
        old_owned = old_state["owned"] if old_state else bytearray(MAX_ENTS)
        sorted_old = sorted(old_ents.keys())
        old_idx = 0
        total_old = len(sorted_old)

        curr_ents = {}
        sync = 0

        trace = frame in trace_set
        if trace:
            print(f"--- TRACING FRAME {frame} ---")
            print(f"    Old frame {old_frame} has {len(old_ents)} entities")
            print(f"    Old entity IDs: {sorted_old[:30]}{'...' if len(sorted_old) > 30 else ''}")

        print_snapshot_header(header, payload_len=len(payload), trace=trace)

        sync_error = False

        # ----------------------------------------------------------------------
        # Entity stream loop
        # Each record begins on a byte boundary:
        #   u16 packed = (sync<<12) | entityId(12)
        #   u8  classId (255 means explicit destroy)
        #   then 1 bit mode + payload for baseline/diff (except destroy)
        # ----------------------------------------------------------------------
        while reader.remaining_bits() >= 24:
            # IMPORTANT: the header is always read aligned
            reader.align_to_byte()
            if reader.remaining_bits() < 24:
                break

            header_bit = reader.tell()  # exact start of the 3-byte header

            packed = reader.read_bits(16)
            raw_cid = reader.read_bits(8)

            eid = packed & ID_MASK
            sval = (packed >> SYNC_SHIFT) & SYNC_MASK
            exp_s = sync & SYNC_MASK

            old_id = sorted_old[old_idx] if old_idx < total_old else 999999

            # ------------------------------------------------------------------
            # IMPLICIT KEEP (core fix):
            # If old_id < eid, copy ONE old entity forward,
            # then rewind to re-read the SAME packet header again.
            # ------------------------------------------------------------------
            if old_id < eid:
                curr_ents[old_id] = old_ents[old_id]
                old_idx += 1

                # rewind EXACTLY the entity header (16+8 bits = 24 bits)
                reader.seek(header_bit)

                if trace:
                    print(f"  [Implicit Keep] Ent {old_id}, rewinding to re-read packet ent {eid}, sync stays {sync}")
                continue

            # ------------------------------------------------------------------
            # From here: we are consuming THIS packet record, so validate sync.
            # ------------------------------------------------------------------
            if sval != exp_s:
                if trace:
                    print(f"  [Ent #{sync}] ID:{eid} Class:{raw_cid} | Sync:{sval} | BitPos:{header_bit}")
                print(f"  [CRITICAL ERROR] Sync Mismatch at Frame {frame}, Ent {eid} old_frame {old_frame}")
                print(f"    Expected {exp_s}, got {sval}")
                print(f"    Current Bit Offset: {header_bit}")
                sync_error = True
                break

            # This record consumes one sync slot
            sync += 1

            # ------------------------------------------------------------------
            # EXPLICIT DESTROY (classId == 255)
            # ------------------------------------------------------------------
            if raw_cid == 255:
                if eid == old_id and old_frame != 0:
                    # true “destroy/remove” record (update path)
                    if trace:
                        print(f"  [Ent #{sync-1}] ID:{eid} -> DESTROY (0xFF, matched old_id)")
                    old_idx += 1
                    continue

                # Otherwise: this is NOT a destroy in the real client logic.
                # Seeing this strongly suggests you are desynced or reading past endPosition.
                if trace:
                    bits_left = reader.remaining_bits() // 8
                    print(f"  [WARN] DESTROY? classId=0xFF but eid={eid} != old_id={old_id} (bits_left_in_stream≈{bits_left})")
                sync_error = True
                break

            # ------------------------------------------------------------------
            # NORMAL ENTITY RECORD: baseline or diff
            # ------------------------------------------------------------------
            cid = str(raw_cid)
            schema = class_table.get(cid)
            class_name = schema.get("name", "NO_SCHEMA") if schema else "NO_SCHEMA"
            if schema is None:
                print(f"[ERROR] No schema for cid {cid} at frame {frame} (eid {eid})")
                sync_error = True
                break

            # Mode bit comes immediately after header for non-destroy
            mode = reader.read_bool()  # True = dense, False = sparse (per your usage)

            verbose_fields = trace

            if trace:
                print(f"  [Ent #{sync-1}] ID:{eid} Class:{cid} ({class_name}) | Sync:{sval}")

            ownerflip_baseline = (
                eid == old_id and
                owned_cur[eid] == 1 and
                old_owned[eid] == 0
            )

            if eid == old_id:
                if ownerflip_baseline:
                    if trace:
                        print(f"    -> UPDATE-ID but OWNERFLIP => BASELINE (oldOwned=0 newOwned=1)")
                    curr_ents[eid] = read_baseline(reader, class_table, cid, mode, verbose=verbose_fields)
                else:
                    if trace:
                        print(f"    -> UPDATE (Diff) Mode: {'Dense' if mode else 'Sparse'}")
                    curr_ents[eid] = read_diff(reader, class_table, old_ents[old_id], cid, mode, verbose=verbose_fields)
                old_idx += 1
            else:
                if trace:
                    print(f"    -> NEW (Baseline)")
                curr_ents[eid] = read_baseline(reader, class_table, cid, mode, verbose=verbose_fields)

        # ----------------------------------------------------------------------
        # End of packet stream: carry forward remaining old entities
        # ----------------------------------------------------------------------
        while old_idx < total_old:
            old_eid = sorted_old[old_idx]
            curr_ents[old_eid] = old_ents[old_eid]
            if trace:
                print(f"  [Carry-forward] Ent {old_eid} (end of stream)")
            old_idx += 1

        # Stop on sync error
        if sync_error:
            print(f"\n[FATAL] Stopping due to sync error at frame {frame}")
            world_hist[frame] = {"ents": curr_ents, "owned": owned_cur}
            break

        # ----------------------------------------------------------------------
        # DUMP ENTITIES AT FRAME 24 - Just a test
        # ----------------------------------------------------------------------
        if frame == 24:
            print(f"\n{'='*20} DUMPING ENTITIES: FRAME {frame} {'='*20}")
            # Sort by ID for readability
            for eid in sorted(curr_ents.keys()):
                ent = curr_ents[eid]
                cid = ent.get('classId')
                
                # Get class name from table
                c_name = "Unknown"
                if cid is not None:
                    c_schema = class_table.get(str(cid))
                    if c_schema:
                        c_name = c_schema.get('name', 'Unknown')

                print(f"[Entity {eid}] Class: {cid} ({c_name})")
                
                # Print fields nicely
                fields = ent.get('fields', {})
                if not fields:
                    print("  (No fields)")
                for fname, fval in fields.items():
                    # Format floats to avoid mess
                    if isinstance(fval, float):
                        print(f"  {fname}: {fval:.4f}")
                    elif isinstance(fval, dict) and 'x' in fval: # Vectors
                        print(f"  {fname}: ({fval.get('x',0):.2f}, {fval.get('y',0):.2f}, {fval.get('z',0):.2f})")
                    else:
                        print(f"  {fname}: {fval}")
            print("="*60 + "\n")

        # Save frame state
        world_hist[frame] = {"ents": curr_ents, "owned": owned_cur}
        if len(world_hist) > MAX_HIST:
            del world_hist[min(world_hist.keys())]

        if trace or frame % 25 == 0:
            print(f"Frame {frame} OK. Entities: {len(curr_ents)}")

    # --------------------------------------------------------------------------
    # Summary
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("FINAL WORLD STATE SUMMARY")
    print("=" * 80)
    print(f"Frames in history: {sorted(world_hist.keys())}")
    if world_hist:
        last_f = max(world_hist.keys())
        print(f"Last frame: {last_f}, entities: {len(world_hist[last_f])}")


if __name__ == "__main__":
    main()