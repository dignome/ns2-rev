import struct

class BinaryReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

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
        Reads a raw block of bits (defined by maxBits in schema), converts to ASCII.
        """
        if max_bits is None or max_bits == 0:
            return ""
            
        # 1. Read the raw integer value of the whole block
        raw_val = self.read_bits(max_bits)
        
        # 2. Convert to bytes (rounding up)
        num_bytes = (max_bits + 7) // 8
        try:
            byte_data = raw_val.to_bytes(num_bytes, byteorder='little')
            # 3. Decode UTF-8 and strip null terminators
            return byte_data.decode('utf-8', errors='ignore').rstrip('\x00')
        except:
            return ""
            
    def align(self):
        """Skips remaining bits in current byte. Used if protocol mandates byte alignment."""
        if self.bit_offset != 0:
            self.bit_offset = 0
            self.byte_offset += 1

# Unpacks data by type and returns the result            
def unpack_field(reader, field):
    """
    Reads a single field based on the schema definition.
    Handles Integers, Floats, Bools, Strings, and Compressed Vectors.
    """
    f_type = field['type']
    f_name = field['name']
    
    # --- 1. Boolean ---
    if f_type == 'Bool':
        return reader.read_bool()

    # --- 2. String ---
    if f_type == 'String':
        max_bits = field.get('maxBits', 0)
        return reader.read_string(max_bits)

    # --- 3. Vector / Position / Angles (3-Component Types) ---
    if f_type in ['Vector', 'Position', 'Angles', 'DebugLine']: 
        # Note: DebugLine has endpoints which are Vectors, but the schema 
        # lists them as type Vector.
        
        # NS2 Vectors usually have 3 compression steps in the JSON (x, y, z)
        comps = field.get('compression', [])
        
        # Helper to read one component based on a compression step
        def read_component(step_info):
            bits = step_info['bits']
            raw_val = reader.read_bits(bits)
            # Decompress: (Raw + Min) * StepValue
            min_raw = step_info.get('min_raw', 0)
            step_val = step_info.get('stepValue', 0)
            # If stepValue is 0, it might be an uncompressed integer passed as float
            if step_val == 0 and bits == 32: return float(raw_val) # Likely raw
            return (raw_val + min_raw) * step_val

        # If we have compression data for 3 axes
        if len(comps) >= 3:
            x = read_component(comps[0])
            y = read_component(comps[1])
            z = read_component(comps[2])
            return {'x': x, 'y': y, 'z': z}
        else:
            # Fallback: Read 3 raw floats (96 bits)
            x = reader.read_float()
            y = reader.read_float()
            z = reader.read_float()
            return {'x': x, 'y': y, 'z': z}

    # --- 4. Integers, Fixed, Time, Angle (Scalar Types) ---
    # These often utilize RangeStep compression
    
    # Check for compression steps first
    compress_steps = field.get('compression', [])
    
    if compress_steps:
        # Default to the first step (Step 0)
        step_info = compress_steps[0]
        
        bits_to_read = step_info['bits']
        raw_value = reader.read_bits(bits_to_read)
        
        # Decompress
        min_raw = step_info.get('min_raw', 0)
        step_val = step_info.get('stepValue', 0)
        
        # Calculate Value
        if step_val != 0:
            val = (raw_value + min_raw) * step_val
        else:
            # If step is 0, it's usually just the raw value (offset by min)
            val = raw_value + min_raw
            
        # Cast based on type
        if f_type == 'Integer':
            return int(val)
        return val # Float/Fixed/Time return as float

    # --- 5. Uncompressed Scalars (Fallback) ---
    max_bits = field.get('maxBits', 32)
    
    if f_type == 'Float':
        # If explicitly 32 bits and no compression, read as IEEE float
        if max_bits == 32:
            return reader.read_float()
        else:
            return reader.read_bits(max_bits) # Rare compressed float without steps
            
    # Default Integer Read
    return reader.read_bits(max_bits)