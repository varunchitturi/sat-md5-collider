import math

def print_word(x):
    b = x
    s = ""
    for _ in range(32):
        s += str(b & 1)
        b = b >> 1
    print(s[::-1])

class MD5:

    S_table = [[7, 12, 17, 22], 
            [5, 9, 14, 20], 
           [4, 11, 16, 23], 
           [6, 10, 15, 21]]
    
    def __init__(self):
        self.a = 0x67452301
        self.b = 0xefcdab89
        self.c = 0x98badcfe
        self.d = 0x10325476
        

    @staticmethod
    def S(i):
        return MD5.S_table[i // 16][i % 4]


    @staticmethod
    def K(i):
        return int(4294967296 * abs(math.sin(i + 1))) & 0xffffffff

    @staticmethod
    def F(b, c, d, i):
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
        x = x & 0xffffffff
        n = MD5.S(i)
        return (((x) << (n)) | ((x) >> (32-(n)))) & 0xffffffff


    @staticmethod
    def combine_words(a, b, c, d, x, i):
        f = MD5.F(b, c, d, i)
        comb = a + f + x + MD5.K(i)
        return MD5.ROT(comb, i) + b
    

    @staticmethod
    def md5_iteration(a, b, c, d, x, i):
        x = int.from_bytes(x, 'little')
        a_new = d
        c_new = b
        d_new = c
        b_new = MD5.combine_words(a, b, c, d, x, i)
        return a_new, b_new, c_new, d_new
    
    @staticmethod
    def md5_padded(input_bytes):
        num_bits = len(input_bytes) * 8
        padding = b"\x80" + 63*b"\x00"
        index = int((num_bits >> 3) & 0x3f)
        if index < 56:
            padLen = (56 - index)
        else:
            padLen = (120 - index)
        
        return input_bytes + padding[:padLen] + (num_bits & 0xffffffff).to_bytes(4, 'little') + (num_bits >> 32 & 0xffffffff).to_bytes(4, 'little')
    
    
    def md5_chunk(self, input_bytes, num_rounds=4):
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
                a, b, c, d = MD5.md5_iteration(a, b, c, d, input_bytes[idx*4:idx*4+4], iter)

        self.a = (self.a + a) & 0xffffffff
        self.b = (self.b + b) & 0xffffffff
        self.c = (self.c + c) & 0xffffffff
        self.d = (self.d + d) & 0xffffffff

    def md5_digest(self, input_bytes, num_rounds=4):
        if len(input_bytes) % 64 != 0:
            input_bytes = self.md5_padded(input_bytes)
        for i in range(0, len(input_bytes), 64):
            self.md5_chunk(input_bytes[i:i+64], num_rounds)
        bytes_list = self.a.to_bytes(4, 'little') + \
                    self.b.to_bytes(4, 'little') + \
                    self.c.to_bytes(4, 'little') + \
                    self.d.to_bytes(4, 'little')
        return int.from_bytes(bytes_list, 'big')


    
    
    
    