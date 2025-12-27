# Generate a Network Structure checksum from its fields using the field name, flag, and order.
from dataclasses import dataclass
from typing import Iterable

U32_MASK = 0xFFFFFFFF

def u32(x: int) -> int:
    return x & U32_MASK

def as_i8(b: int) -> int:
    """0..255 -> -128..127"""
    b &= 0xFF
    return b - 256 if b & 0x80 else b

def combine32(seed: int, value: int) -> int:
    """Boost-like hash combine in 32-bit space."""
    seed = u32(seed)
    value = u32(value)
    tweak = u32(value + 0x9E3779B9 + u32(seed << 6) + (seed >> 2))
    return u32(seed ^ tweak)

def hash_field_name(raw: bytes) -> int:
    """
    Name hash: djb2-ish, but uses signed bytes and stops at NUL.
    """
    h = 5381
    for b in raw:
        if b == 0:
            break

        h = u32(((h << 5) + h) + as_i8(b))
    return h

def mix_flags(flags: int) -> int:
    """
    32-bit avalanche-ish mixer derived from the observed behavior.
    """
    x = u32(flags)
    x = u32((x ^ 0x3D) ^ (x >> 16))
    x = u32(x * 9)
    x = u32(x ^ (x >> 4))
    x = u32(x * 0x27D4EB2D)
    x = u32(x ^ (x >> 15))
    return x

def checksum_field(field_type: int, flags: int) -> int:
    """
    Field checksum depends on 4 bytes of type and the flags.
    """
    t = u32(field_type)
    b = [(t >> (8 * i)) & 0xFF for i in range(4)]  # little-endian bytes

    s = u32((as_i8(b[0]) - 0x1F6D3977) ^ 0x4E67C6A7)

    for bi in b[1:]:
        step = u32(u32(s << 5) + (s >> 2) + as_i8(bi))
        s = u32(s ^ step)

    return combine32(s, mix_flags(flags))

@dataclass(frozen=True)
class Field:
    name_bytes: bytes  # include NUL terminator if you read from memory; stop at first 0x00 either way
    type_u32: int
    flags_u32: int

def checksum_structure(fields: Iterable[Field]) -> int:
    seed = 0
    for f in fields:
        seed = combine32(seed, hash_field_name(f.name_bytes))
        seed = combine32(seed, checksum_field(f.type_u32, f.flags_u32))
    return u32(seed)

# Example:
# Field is name, type (int), flags
#        Angle = 0x0,
#        Angles = 0x1,
#        Bool = 0x2,
#        Fixed = 0x3, <- often used as Float
#        Integer = 0x4,
#        Position = 0x5,
#        String = 0x6,
#        Vector = 0x7,
#        Float = 0x8,
#        Time = 0x9

if __name__ == "__main__":
    print("PlaySoundMessage: ", end="")
    demo1 = [
        Field(b"parent\0", 4, 0x00000000),
        Field(b"resource\0", 4, 0x00000000),
        Field(b"modifier\0", 3, 0x00000000),
        Field(b"origin\0", 5, 0x00000000)
    ]
    print(hex(checksum_structure(demo1))[2:].upper())
    
    print("RTGraph: ", end="")
    demo2 = [
        Field(b"destroyed\0", 2, 0x00000000),
        Field(b"gameMinute\0", 3, 0x00000000),
        Field(b"teamNumber\0", 4, 0x00000000)
    ]
    print(hex(checksum_structure(demo2))[2:].upper())