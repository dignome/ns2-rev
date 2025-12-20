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