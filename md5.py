"""MD5 compression function (teaching/demo implementation).

This module provides a small, readable implementation of the MD5 compression
function that can execute a configurable number of rounds (1–4 rounds = 16
steps each; full MD5 uses 4). The implementation is stateful: the internal
state words a, b, c, d are updated as 512-bit blocks are processed.

"""
import math

def print_word(x):
    """Print a 32-bit integer as a 32-character bitstring (MSB first)."""
    b = x
    s = ""
    for _ in range(32):
        s += str(b & 1)
        b = b >> 1
    print(s[::-1])

class MD5:

    # Per-round left-rotation amounts (RFC 1321)
    S_table = [[7, 12, 17, 22], 
            [5, 9, 14, 20], 
           [4, 11, 16, 23], 
           [6, 10, 15, 21]]
    
    def __init__(self):
        """Initialize to the MD5 initial vector (IV)."""
        self.a = 0x67452301
        self.b = 0xefcdab89
        self.c = 0x98badcfe
        self.d = 0x10325476
        

    @staticmethod
    def S(i):
        """Return the rotation amount for step index i (0 ≤ i < 64)."""
        return MD5.S_table[i // 16][i % 4]


    @staticmethod
    def K(i):
        """Return the i-th sine-derived constant (floor(2^32 · |sin(i+1)|))."""
        return int(4294967296 * abs(math.sin(i + 1))) & 0xffffffff

    @staticmethod
    def F(b, c, d, i):
        """MD5 non-linear boolean function selected by round index i.

        Round 0 (i < 16): (b & c) | (~b & d)
        Round 1 (i < 32): (b & d) | (c & ~d)
        Round 2 (i < 48): b ^ c ^ d
        Round 3 (i < 64): c ^ (b | ~d)
        """
        if i < 16:
            return (b & c) | (~b & d)
        elif i < 32:
            return (b & d) | (c & ~d)
        elif i < 48:
            return b ^ c ^ d
        elif i < 64:
            return c ^ (b | ~d)
        else:
            raise ValueError("Invalid loop index")


    @staticmethod
    def ROT(x, i):
        """Rotate x left by S(i) bits, modulo 2^32."""
        x = x & 0xffffffff
        n = MD5.S(i)
        return (((x) << (n)) | ((x) >> (32-(n)))) & 0xffffffff


    @staticmethod
    def combine_words(a, b, c, d, x, i):
        """Compute b + ROT(a + F(b,c,d) + x + K(i), S(i)) (mod 2^32)."""
        f = MD5.F(b, c, d, i)
        comb = a + f + x + MD5.K(i)
        return MD5.ROT(comb, i) + b
    

    @staticmethod
    def md5_iteration(a, b, c, d, x, i):
        """Perform one MD5 step (i) on state (a,b,c,d) with 32-bit word x.

        The 32-bit message word x is provided as 4 bytes and interpreted
        little-endian, per MD5's specification.
        """
        x = int.from_bytes(x, 'little')
        a_new = d
        c_new = b
        d_new = c
        b_new = MD5.combine_words(a, b, c, d, x, i)
        return a_new, b_new, c_new, d_new
    
    @staticmethod
    def md5_padded(input_bytes):
        """Return input_bytes padded to a multiple of 64 bytes per MD5.

        Padding: 0x80 byte, then 0x00 bytes up to 56 mod 64, then the
        64-bit little-endian length (in bits).
        """
        num_bits = len(input_bytes) * 8
        padding = b"\x80" + 63*b"\x00"  # at most 63 bytes added before length
        index = int((num_bits >> 3) & 0x3f)
        if index < 56:
            padLen = (56 - index)
        else:
            padLen = (120 - index)
        
        # Append 64-bit bit-length in little-endian as two 32-bit words
        return input_bytes + padding[:padLen] + (num_bits & 0xffffffff).to_bytes(4, 'little') + (num_bits >> 32 & 0xffffffff).to_bytes(4, 'little')
    
    
    def md5_chunk(self, input_bytes, num_rounds=4):
        """Process one 64-byte chunk and update internal state.

        The message word schedule matches MD5's four rounds:
        - Round 0: index = j
        - Round 1: index = (5·iter + 1) mod 16
        - Round 2: index = (3·iter + 5) mod 16
        - Round 3: index = (7·iter) mod 16
        """
        assert num_rounds in [1, 2, 3, 4]
        assert len(input_bytes) == 64
        a = self.a
        b = self.b
        c = self.c
        d = self.d
        
        for i in range(num_rounds):
            for j in range(16):
                iter = i*16 + j
                idx = iter % 16
                if i == 1:
                    idx = (5*iter + 1) % 16
                elif i == 2:
                    idx = (3*iter + 5) % 16
                elif i == 3:
                    idx = (7*iter) % 16
                # x is taken as 4 bytes; endianness is handled in md5_iteration
                a, b, c, d = MD5.md5_iteration(a, b, c, d, input_bytes[idx*4:idx*4+4], iter)

        self.a = (self.a + a) & 0xffffffff
        self.b = (self.b + b) & 0xffffffff
        self.c = (self.c + c) & 0xffffffff
        self.d = (self.d + d) & 0xffffffff

    def md5_digest(self, input_bytes, num_rounds=4):
        """Compute the MD5 digest of input_bytes as a 128-bit integer.

        If input length is not a multiple of 64 bytes, the input is padded.
        The return value packs a,b,c,d (little-endian words) into a big-endian
        integer for convenience.
        """
        if len(input_bytes) % 64 != 0:
            input_bytes = self.md5_padded(input_bytes)
        for i in range(0, len(input_bytes), 64):
            self.md5_chunk(input_bytes[i:i+64], num_rounds)
        bytes_list = self.a.to_bytes(4, 'little') + \
                    self.b.to_bytes(4, 'little') + \
                    self.c.to_bytes(4, 'little') + \
                    self.d.to_bytes(4, 'little')
        return int.from_bytes(bytes_list, 'big')


    
    
    
    