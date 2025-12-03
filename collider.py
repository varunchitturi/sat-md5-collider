from pysat.solvers import Solver
from md5 import MD5

class MD5Collider:
    
    def __init__(self, input_bytes, exclude_input_bits=[], target_digest=None):
        assert input_bytes is None or len(input_bytes) % 64 == 0
        num_chunks = len(input_bytes) // 64 if input_bytes is not None else 1
        self.solver = Solver(name='g4')
        self.var_idx = 1
        self.a = []
        self.b  = []
        self.c = []
        self.d = []
        self.x = []
        self.target_digest = target_digest
        self._init_vars(num_chunks)
        if input_bytes is not None:
            for i in range(len(input_bytes)):
                exclude_bits = []
                for exclude_bit in exclude_input_bits:
                    if exclude_bit // 8 == i:
                        exclude_bits.append(exclude_bit % 8)
                byte = self._get_byte_vars(self.x, i)
                self._add_constant(byte, input_bytes[i], exclude_bits=exclude_bits)
        self._add_constant(self.a, 0x67452301)
        self._add_constant(self.b, 0xefcdab89)
        self._add_constant(self.c, 0x98badcfe)
        self._add_constant(self.d, 0x10325476)
    
    def _init_number(self, num_bits):
        num = []
        for _ in range(num_bits):
            num.append(self.var_idx)
            self.var_idx += 1
        return num
    
    def _init_bit(self):
        bit_var = self.var_idx
        self.var_idx += 1
        return bit_var

    def _init_vars(self, num_chunks):
        self.x = self._init_number(512 * num_chunks)
        self.a = self._init_number(32)
        self.b = self._init_number(32)
        self.c = self._init_number(32)
        self.d = self._init_number(32)
        
    # Gets the ith byte of the bit array where the left most (MSB) byte is the 0th byte     
    def _get_byte_vars(self, bit_array, byte_idx):
        return bit_array[byte_idx*8:(byte_idx+1)*8]
    
     # Gets the ith word of the bit array where the left most (MSB) word is the 0th word     
    def _get_word_vars(self, bit_array, word_idx):
        return bit_array[word_idx*32:(word_idx+1)*32]

    def _convert_endianness(self, bit_array):
        new_bit_array = []
        for i in range(len(bit_array) // 8 - 1, -1, -1):
            byte_vars = self._get_byte_vars(bit_array, i)
            new_bit_array.extend(byte_vars)
        return new_bit_array
        
    def _add_equality(self, a, b):
        for i in range(len(a)):
            self.solver.add_clause([-a[i], b[i]])
            self.solver.add_clause([a[i], -b[i]])

    def _add_constant(self, bit_array, constant, exclude_bits=[]):
        assert 2 ** len(bit_array) > constant
        for i in range(len(bit_array)):
            multiplier = 1
            if i in exclude_bits:
                multiplier = -1
            c_bit = (constant >> (len(bit_array) - i - 1)) & 1
            if c_bit == 1:
                self.solver.add_clause([multiplier * bit_array[i]])
            else:
                self.solver.add_clause([multiplier * -bit_array[i]])
        return bit_array

    def _add_or(self, a, b, c=None):
        assert len(a) == len(b)
        if c is not None:
            assert len(a) == len(c)
        else:
            c = self._init_number(len(a))
        for i in range(len(a)):
            self.solver.add_clause([a[i], b[i], -c[i]])
            self.solver.add_clause([-a[i], c[i]])
            self.solver.add_clause([-b[i], c[i]])
        return c
    
    def _add_and(self, a, b, c=None):
        assert len(a) == len(b)
        if c is not None:
            assert len(a) == len(c)
        else:
            c = self._init_number(len(a))
        for i in range(len(a)):
            self.solver.add_clause([-a[i], -b[i], c[i]])
            self.solver.add_clause([a[i], -c[i]])
            self.solver.add_clause([b[i], -c[i]])
        return c

    def _add_xor(self, a, b, c=None):
        assert len(a) == len(b)
        if c is not None:
            assert len(a) == len(c)
        else:
            c = self._init_number(len(a))
        for i in range(len(a)):
            self.solver.add_clause([-a[i], -b[i], -c[i]])
            self.solver.add_clause([a[i], b[i], -c[i]])
            self.solver.add_clause([a[i], -b[i], c[i]])
            self.solver.add_clause([-a[i], b[i], c[i]])
        return c
    
    def _add_not(self, a, b=None):
        if b is not None:
            assert len(a) == len(b)
        else:
            b = self._init_number(len(a))
        for i in range(len(a)):
            self.solver.add_clause([-a[i], -b[i]])
            self.solver.add_clause([a[i], b[i]])
        return b

    def _add_sum(self, a, b, c=None):
        assert len(a) == len(b)
        if c is not None:
            assert len(a) == len(c)
        else:
            c = self._init_number(len(a))
        carry = self._init_number(len(a))
        for i in range(len(a)):
            idx = len(a) - i - 1
            if i == 0:
                self._add_xor([a[idx]], [b[idx]], [c[idx]])
                if idx > 0:
                    self._add_and([a[idx]], [b[idx]], [carry[idx-1]])
            else:
                ab_xor = self._init_bit()
                self._add_xor([a[idx]], [b[idx]], [ab_xor])
                self._add_xor([carry[idx]], [ab_xor], [c[idx]])
                if idx > 0:
                    cout1 = self._init_bit()
                    cout2 = self._init_bit()
                    self._add_and([a[idx]], [b[idx]], [cout1])
                    self._add_and([carry[idx]], [ab_xor], [cout2])
                    self._add_or([cout1], [cout2], [carry[idx-1]])
        return c
    
    def _add_rotate_left(self, a, n, b=None):
        if b is not None:
            assert len(a) == len(b)
        else:
            b = self._init_number(len(a))
        for i in range(len(a)):
            b_idx = (len(a)+ i - n) % len(a)
            self.solver.add_clause([a[i], -b[b_idx]])
            self.solver.add_clause([-a[i], b[b_idx]])
        return b
    
    def add_F(self, b, c, d, i):
        if i < 16:
            return self._add_or(self._add_and(b, c), self._add_and(self._add_not(b), d))
        elif i < 32:
            return self._add_or(self._add_and(b, d), self._add_and(c, self._add_not(d)))
        elif i < 48:
            return self._add_xor(self._add_xor(b, c), d)
        elif i < 64:
            return self._add_xor(c, self._add_or(b, self._add_not(d)))
        else:
            raise ValueError("Invalid loop index")
    
    def add_combine_words(self, a, b, c, d, x, i):
        f = self.add_F(b, c, d, i)
        k = self._add_constant(self._init_number(32), MD5.K(i))        
        comb = self._add_sum(self._add_sum(a, f), self._add_sum(x, k))
        rot = self._add_rotate_left(comb, MD5.S(i))
        return self._add_sum(rot, b)
    
    def add_md5_iteration(self, a, b, c, d, x, i):
        a_new = d
        c_new = b
        d_new = c
        b_new = self.add_combine_words(a, b, c, d, x, i)
        return a_new, b_new, c_new, d_new
    
    def solve_md5_chunk(self, chunk_idx, num_rounds=4):
        
        assert num_rounds in [1, 2, 3, 4]
                
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
                input_word = self._convert_endianness(self._get_word_vars(self.x, chunk_idx*16 + idx))
                a, b, c, d = self.add_md5_iteration(a, b, c, d, input_word, iter)

        self.a = self._add_sum(self.a, a)
        self.b = self._add_sum(self.b, b)
        self.c = self._add_sum(self.c, c)
        self.d = self._add_sum(self.d, d)
        
    
    def solve_md5(self, num_rounds=4):
        for i in range(len(self.x) // 512):
            self.solve_md5_chunk(i, num_rounds)
            
        if self.target_digest is not None:
            self._add_constant(self._convert_endianness(self.a),
                               self.target_digest >> 96)
            self._add_constant(self._convert_endianness(self.b),
                               (self.target_digest >> 64) & 0xffffffff)
            self._add_constant(self._convert_endianness(self.c),
                               (self.target_digest >> 32) & 0xffffffff)
            self._add_constant(self._convert_endianness(self.d),
                               self.target_digest & 0xffffffff)
        
        sat = self.solver.solve_limited(expect_interrupt=True)
        if not sat:
            return False, None
        return sat, self.process_solution(self.solver.get_model())
    
    def solution_to_bytes(self, model, vars, convert_endianness=False):
        if convert_endianness:
            vars = self._convert_endianness(vars)
        byte_vals = b""
        byte = 0
        for j, bit_var in enumerate(vars):
            bit_val = model[bit_var-1] > 0
            byte |= bit_val << (8 - (j % 8) - 1)
            if j % 8 == 7:
                byte_vals += byte.to_bytes(1, 'big')
                byte = 0
        return byte_vals
    
    def process_solution(self, model):
        a = self.solution_to_bytes(model, self.a, True)
        b = self.solution_to_bytes(model, self.b, True)
        c = self.solution_to_bytes(model, self.c, True)
        d = self.solution_to_bytes(model, self.d, True)
        x = self.solution_to_bytes(model, self.x)
        return x, int.from_bytes(a + b + c + d, 'big')
                
    def print_word(self, word, model):
        for i in range(32):
            if model[word[i]]:
                print("1", end="")
            else:
                print("0", end="")
        print()