import struct

class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        
    def position(self, pos: int):
        self.offset = pos
        return
        
    def skip(self, length: int):
        self.offset = min(len(self.data), self.offset + length)
        return
        
    def tell(self) -> int:
        return self.offset

    def remaining(self) -> int:
        return max(0, len(self.data) - self.offset)

    def read_float32(self) -> float:
        val = struct.unpack('<f', self.data[self.offset:self.offset+4])[0]
        self.offset += 4
        return val

    def read_int8(self) -> int:
        # signed byte
        b = self.data[self.offset]
        self.offset += 1
        return b - 256 if b >= 128 else b

    def read_int8s(self, count: int):
        return [self.read_int8() for _ in range(count)]

    def read_uint32(self):
        val = struct.unpack('<I', self.data[self.offset:self.offset+4])[0]
        self.offset += 4
        return val

    def read_uint16(self):
        val = struct.unpack('<H', self.data[self.offset:self.offset+2])[0]
        self.offset += 2
        return val

    def read_uint64(self):
        val = struct.unpack('<Q', self.data[self.offset:self.offset+8])[0]
        self.offset += 8
        return val

    def read_uint8(self):
        val = self.data[self.offset]
        self.offset += 1
        return val

    def read_bool(self):
        # M4::BinaryWriter::WriteBool writes a uint32
        return self.read_uint32() != 0

    def read_string_len(self):
        # Writes length (uint32) then chars (no null)
        length = self.read_uint32()
        s = self.data[self.offset:self.offset+length].decode('utf-8', errors='replace')
        self.offset += length
        return s

    def read_bytes(self, length):
        val = self.data[self.offset:self.offset+length]
        self.offset += length
        return val

    def read_string_null(self):
        # Reads until 0x00
        end = self.data.find(b'\x00', self.offset)
        if end == -1:
            # Fallback if malformed
            s = self.data[self.offset:].decode('utf-8', errors='replace')
            self.offset = len(self.data)
        else:
            s = self.data[self.offset:end].decode('utf-8', errors='replace')
            self.offset = end + 1
        return s
        
    def read_ipv4_u32_le(self) -> str:
        """
        Reads a little-endian u32 IPv4 address and returns dotted-quad.
        Equivalent to inet_ntoa(pack('<I', raw_u32)) but without struct/socket.
        """
        raw = self.read_uint32()
        b0 = (raw >> 0) & 0xFF
        b1 = (raw >> 8) & 0xFF
        b2 = (raw >> 16) & 0xFF
        b3 = (raw >> 24) & 0xFF
        return f"{b0}.{b1}.{b2}.{b3}"
        
    def read_f32_bits(self) -> float:
        # matches decomp behavior: read u32 then assign into float field
        u = self.read_uint32()
        return struct.unpack('<f', struct.pack('<I', u & 0xFFFFFFFF))[0]

    def read_bool_u32_lowbyte(self) -> bool:
        # decomp reads 4 bytes then casts to uint8
        v = self.read_uint32()
        return (v & 0xFF) != 0
        
    def read_float64(self) -> float:
        val = struct.unpack('<d', self.data[self.offset:self.offset+8])[0]
        self.offset += 8
        return val
        
    def read_int32(self) -> int:
        val = struct.unpack('<i', self.data[self.offset:self.offset+4])[0]
        self.offset += 4
        return val
        

class BitReader:
    def __init__(self, data):
        self.data = data
        self.byte_offset = 0
        self.bit_offset = 0  # 0..7

    def read_bits(self, num_bits):
        """
        Reads 'num_bits' from the stream.
        Logic matches M4::BitReader::ReadBlock (LSB first, spanning byte boundaries).
        """
        value = 0
        bits_read = 0
        
        while bits_read < num_bits:
            if self.byte_offset >= len(self.data):
                return value 
            
            # 1. Calculate bits available in current byte
            remaining_in_byte = 8 - self.bit_offset
            
            # 2. Determine how many we need vs how many are available
            to_read = min(num_bits - bits_read, remaining_in_byte)
            
            # 3. Create mask (e.g., to_read=3 -> 111 binary -> 7)
            mask = (1 << to_read) - 1
            
            # 4. Extract bits starting at bit_offset
            # The assembly uses >> to shift past used bits, then & mask
            chunk = (self.data[self.byte_offset] >> self.bit_offset) & mask
            
            # 5. Add to result
            # We shift the chunk 'up' by bits_read because these are higher-order bits in the final integer
            value |= (chunk << bits_read)
            
            # 6. Advance counters
            bits_read += to_read
            self.bit_offset += to_read
            
            if self.bit_offset == 8:
                self.bit_offset = 0
                self.byte_offset += 1
        
        return value
        
    def remaining_bits(self) -> int:
        return (len(self.data) - self.byte_offset) * 8 - self.bit_offset
        
    def read_varint(reader):
        """
        Reads a 7-bit variable-length integer from the bit stream.
        Used for reading field counts and indices in Diff updates.
        """
        result = 0
        shift = 0
        while True:
            # Read 8 bits: 7 data bits + 1 continuation bit
            val = reader.read_bits(8)
            result |= (val & 0x7F) << shift
            if not (val & 0x80):  # Check continuation bit (MSB)
                break
            shift += 7
        return result

    def read_bool(self):
        """Matches M4::BitReader::ReadBool - Reads 1 bit."""
        return self.read_bits(1) == 1

    def read_float(self):
        """
        Matches NetworkField_Type_Float.
        Reads 32 bits as an integer, then re-interprets bytes as IEEE 754 float.
        """
        bits = self.read_bits(32)
        try:
            # Convert Int -> Bytes -> Float
            return struct.unpack('<f', bits.to_bytes(4, byteorder='little'))[0]
        except:
            return 0.0

    def read_string(self, max_bits):
        """
        Matches NetworkField_Type_String / ReadBlock2.
        Reads a raw block of bits (defined by numBits in schema), converts to ASCII.
        """
        if max_bits is None or max_bits == 0:
            return ""
            
        # 1. Read the raw integer value of the whole block
        raw_val = self.read_bits(max_bits)
        
        # 2. Convert to bytes (rounding up)
        num_bytes = (max_bits + 7) // 8
        try:
            byte_data = raw_val.to_bytes(num_bytes, byteorder='little')
            
            # Stop on NULL
            byte_data = byte_data.split(b"\x00", 1)[0]
            
            # 3. Decode UTF-8 and strip null terminators
            return byte_data.decode('utf-8', errors='ignore').rstrip('\x00')
        except:
            return ""
            
    def align(self):
        """Skips remaining bits in current byte. Used if protocol mandates byte alignment."""
        if self.bit_offset != 0:
            self.bit_offset = 0
            self.byte_offset += 1

# Type Map
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

# Unpacks data by type and returns the result            
def unpack_field(reader, field):
    """
    Reads a single field based on the schema definition.
    Handles Floats, Bools, Strings, and component/rangestep encoded types.
    """
    f_type = field.get('type')
    # f_name = field.get('name') # Unused but kept for reference

    # --- 1. Boolean ---
    if f_type == NET_TYPE_BOOL:
        return reader.read_bool()

    # --- 2. String ---
    if f_type == NET_TYPE_STRING:
        # Note: Schema usually uses 'maxBits' or 'numBits' for string block size
        max_bits = field.get('numBits', 0)
        return reader.read_string(max_bits)

    # Helper to read one component described by a range-step entry
    def u32_to_f32(u: int) -> float:
        return struct.unpack("<f", struct.pack("<I", u & 0xFFFFFFFF))[0]

    def read_component(step_info):
        bits = int(step_info.get('bits', 0))

        min_raw  = step_info.get('min_raw', 0) or 0
        step_val = step_info.get('stepValue', 0) or 0
        range_raw = step_info.get('range_raw', 0) or 0

        # ✅ Special-case: 32-bit component with no quantization metadata
        # Treat as raw IEEE-754 float32 stored in the bitstream.
        if bits == 32 and step_val == 0 and min_raw == 0 and range_raw == 0:
            raw_u32 = reader.read_bits(32)
            return u32_to_f32(raw_u32)

        raw_val = reader.read_bits(bits)

        # Existing decode rule you’re using:
        # value = (raw + min_raw) * stepValue
        if step_val:
            return (raw_val + min_raw) * step_val
        else:
            return raw_val + min_raw

    # --- 3. 3-Component Types (Vector, Position, Angles) ---
    if f_type in [NET_TYPE_VECTOR, NET_TYPE_POSITION, NET_TYPE_ANGLES]:
        comps = field.get('components', [])

        if len(comps) >= 3:
            x = read_component(comps[0])
            y = read_component(comps[1])
            z = read_component(comps[2])
            return {'x': float(x), 'y': float(y), 'z': float(z)}
        else:
            # Fallback: raw floats
            x = reader.read_float()
            y = reader.read_float()
            z = reader.read_float()
            return {'x': x, 'y': y, 'z': z}

    # --- 4. Scalar Types that may use a single component (range step) ---
    # Integer / Fixed / Time / Angle / Float often use components[0]
    comps = field.get('components', [])
    if comps:
        val = read_component(comps[0])
        if f_type == NET_TYPE_INTEGER:
            return int(val)
        return float(val)  # Fixed/Time/Angle/Float -> float

    # --- 5. Uncompressed Scalars (Fallback) ---
    max_bits = field.get('numBits', 32)

    if f_type == NET_TYPE_FLOAT:
        if max_bits == 32:
            return reader.read_float()
        return reader.read_bits(max_bits)

    if f_type == NET_TYPE_INTEGER:
        return reader.read_bits(max_bits)

    # Default: read bits
    return reader.read_bits(max_bits)