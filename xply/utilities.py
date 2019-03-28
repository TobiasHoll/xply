import itertools
import string
import typing

# Chunk iterators
def chunk(iterable: typing.Iterable[typing.Any], chunk_size: int) -> typing.Iterator[typing.List[typing.Any]]:
    '''Splits the given iterable into chunks of a fixed size'''
    iterator = iter(iterable)
    while True:
        chunk = list(itertools.islice(iterator, chunk_size))
        if not chunk:
            return
        yield chunk

# Hex dumps
_hexdump_print = set(string.printable) - set('\f\v\t\n\r')
def hexdump(data: typing.Iterable[int], chunk_size: int = 16) -> typing.Iterator[str]:
    '''Formats a hexdump, with chunk_size bytes per line'''
    offset = 0
    for block in chunk(data, chunk_size):
        # Hex-encode all the bytes
        encoded_bytes = ('{:02X}'.format(b) for b in block)

        # Add extra spacing if the chunk size is a multiple of 8
        if chunk_size % 8 == 0 and chunk_size > 8:
            blocks = (' '.join(block) for block in chunk(encoded_bytes, 8))
            encoded_chunk = '  '.join(blocks)
            expected_length = 3 * chunk_size - 1 + (chunk_size // 8 - 1)
        else:
            encoded_chunk = ' '.join(encoded_bytes)
            expected_length = 3 * chunk_size - 1
        encoded_chunk += ' ' * (expected_length - len(encoded_chunk))

        # Create the ASCII representation
        chars = (chr(b) for b in block)
        ascii_chunk = ''.join(c if c in _hexdump_print else '.' for c in chars)

        # Format the entire thing
        yield '{:08X}: {}  {}'.format(offset, encoded_chunk, ascii_chunk)

def parse_hexdump(data: str) -> bytes:
    '''Parses a hexdump (in the general format produced by hexdump(...))'''
    result = b''
    # In each line, extract the hex-encoded bytes in the middle
    for line in data.split('\n'):
        line = line.strip()
        middle = line.split(' ', 1)[1].rsplit(' ', 1)[0].strip()
        # ... and add them to the result
        result += bytes.fromhex(result.replace(' ', ''))
    return result
