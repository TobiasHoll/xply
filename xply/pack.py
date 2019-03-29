from __future__ import annotations

import enum
import functools
import struct
import typing

class endianness(enum.Enum):
    '''Endianness of packed data'''
    little = 0
    big = 1

    def to_struct(self):
        '''Convert the endianness into the corresponding python struct marker'''
        return {
            endianness.little: '<',
            endianness.big:    '>'
        }[self]

# Bit operations
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(b1 ^ b2 for b1, b2 in zip(a, b))

def bit_and(a: bytes, b: bytes) -> bytes:
    return bytes(b1 & b2 for b1, b2 in zip(a, b))

def bit_or(a: bytes, b: bytes) -> bytes:
    return bytes(b1 | b2 for b1, b2 in zip(a, b))

def neg(a: bytes) -> bytes:
    return bytes((256 + ~b1) & 0xFF for b1 in a)

# Shorthand class function generation
def _pack_shorthand(generic_pack, generic_unpack):
    def decorator(fmt_class):
        # Store the shorthand names
        fmt_class._shorthand = []

        # For each member, generate a pack_{} and unpack_{} function
        for name, fmt in fmt_class.__members__.items():
            # Function names
            pack_name   = 'pack_{}'.format(name)
            unpack_name = 'unpack_{}'.format(name)
            fmt_class._shorthand.extend([pack_name, unpack_name])

            # The specific pack function should delegate to generic_pack
            pack   = functools.partial(generic_pack,   fmt)
            unpack = functools.partial(generic_unpack, fmt)

            # Store the members in the class (for now)
            setattr(fmt_class, pack_name,   pack)
            setattr(fmt_class, unpack_name, unpack)
        return fmt_class
    return decorator

# Packing and unpacking
def pack_integer(fmt: integer_format, integer: int, endian: endianness = endianness.little) -> bytes:
    '''Pack an integer'''
    return struct.pack(endian.to_struct() + fmt.to_struct(), integer)

def unpack_integer(fmt: integer_format, data: bytes, endian: endianness = endianness.little) -> int:
    '''Unpack an integer'''
    return struct.unpack(endian.to_struct() + fmt.to_struct(), data)[0]

@_pack_shorthand(pack_integer, unpack_integer)
class integer_format(enum.Enum):
    '''Packing formats'''
    u64 = 0
    i64 = 1
    u32 = 2
    i32 = 3
    u16 = 4
    i16 = 5
    u8  = 6
    i8  = 7

    def to_struct(self):
        '''Convert the packing into the corresponding python struct marker'''
        return {
            integer_format.u64:      "Q",
            integer_format.i64:      "q",
            integer_format.u32:      "I",
            integer_format.i32:      "i",
            integer_format.u16:      "H",
            integer_format.i16:      "h",
            integer_format.u8:       "B",
            integer_format.i8:       "b",
        }[self]


# Pull shorthand functions for integer packing into the package
for shorthand_name in integer_format._shorthand:
    globals()[shorthand_name] = getattr(integer_format, shorthand_name)
