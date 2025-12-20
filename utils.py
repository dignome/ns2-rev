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
        """Reads 'num_bits' from the stream, handling unaligned access."""
        value = 0
        bits_read = 0
        
        while bits_read < num_bits:
            if self.byte_offset >= len(self.data):
                # Return what we have if we hit EOF (common in fuzzy parsing)
                return value 
            
            # How many bits are left in the current byte?
            remaining_in_byte = 8 - self.bit_offset
            
            # How many bits do we need to grab from this byte?
            to_read = min(num_bits - bits_read, remaining_in_byte)
            
            # Create a mask to extract specific bits
            # Example: Reading 3 bits. Mask = 0b111 (7)
            mask = (1 << to_read) - 1
            
            # Shift the byte down to the current bit_offset to align LSB
            # Then apply mask to get the bits
            chunk = (self.data[self.byte_offset] >> self.bit_offset) & mask
            
            # Add these bits to our accumulated value
            # We insert them at the current 'bits_read' position (Little Endian logic)
            value |= (chunk << bits_read)
            
            # Advance counters
            bits_read += to_read
            self.bit_offset += to_read
            
            # If we finished this byte, move to the next
            if self.bit_offset == 8:
                self.bit_offset = 0
                self.byte_offset += 1
        
        return value

    def read_uint(self):
        """
        Reads a Variable Length Integer (VInt/VarInt).
        Format: 7 bits of data per byte. 8th bit is 'More' flag.
        Used by M4::BitWriter::WriteUInt.
        """
        val = 0
        shift = 0
        while True:
            # Read 8 bits from the bitstream (not necessarily byte-aligned!)
            byte_val = self.read_bits(8)
            
            # Payload is low 7 bits
            val |= (byte_val & 0x7F) << shift
            
            # Check high bit (0x80) for "More" flag
            if not (byte_val & 0x80):
                break
            shift += 7
            
            # Safety break for malformed packets
            if shift > 64: break 
            
        return val

    def read_float(self):
        """
        Reads 32 bits and interprets them as a float.
        Corresponds to M4::BitWriter::WriteBlock(..., 0x20).
        """
        bits = self.read_bits(32)
        # Pack integer bits back to bytes, then unpack as float
        try:
            return struct.unpack('<f', struct.pack('<I', bits))[0]
        except:
            return 0.0