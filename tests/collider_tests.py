import unittest
from collider import MD5Collider
from md5 import MD5
import pysat
from threading import Timer


class TestMD5ColliderAddConstraints(unittest.TestCase):
    def setUp(self):
        self.collider = MD5Collider(MD5.md5_padded(b"Hello, World!"))

    def test_add_constant_sets_bits_correctly_msb_first(self):
        bits = [self.collider._init_bit() for _ in range(4)]
        self.collider._add_constant(bits, 0b1010)
        sat, model = self.collider.solver.solve()
        self.assertTrue(sat)
        # MSB first mapping in add_constant
        expected = [True, False, True, False]
        # model can be list (index by var id) or dict-like
        for var_id, exp in zip(bits, expected):
            if isinstance(model, dict):
                self.assertEqual(bool(model[var_id]), exp)
            else:
                self.assertEqual(bool(model[var_id]), exp)

    def test_add_or_truth_table_explicit_output(self):
        a = [1]
        b = [2]
        c = [3]
        self.collider._add_or(a, b, c)
        for a_val in (False, True):
            for b_val in (False, True):
                for c_val in (False, True):
                    assumps = [(1 if a_val else -1), (2 if b_val else -2), (3 if c_val else -3)]
                    sat, _ = self.collider.solver.solve(assumptions=assumps)
                    self.assertEqual(sat, (a_val or b_val) == c_val)

    def test_add_and_truth_table_explicit_output(self):
        a = [4]
        b = [5]
        c = [6]
        self.collider._add_and(a, b, c)
        for a_val in (False, True):
            for b_val in (False, True):
                for c_val in (False, True):
                    assumps = [(4 if a_val else -4), (5 if b_val else -5), (6 if c_val else -6)]
                    sat = self.collider.solver.solve(assumptions=assumps)
                    self.assertEqual(sat, (a_val and b_val) == c_val)

    def test_add_xor_truth_table_explicit_output(self):
        a = [7]
        b = [8]
        c = [9]
        self.collider._add_xor(a, b, c)
        for a_val in (False, True):
            for b_val in (False, True):
                for c_val in (False, True):
                    assumps = [(7 if a_val else -7), (8 if b_val else -8), (9 if c_val else -9)]
                    sat = self.collider.solver.solve(assumptions=assumps)
                    self.assertEqual(sat, (a_val ^ b_val) == c_val)

    def test_add_not_truth_table_explicit_output(self):
        a = [11]
        b = [12]
        self.collider._add_not(a, b)
        for a_val in (False, True):
            for b_val in (False, True):
                assumps = [(11 if a_val else -11), (12 if b_val else -12)]
                sat = self.collider.solver.solve(assumptions=assumps)
                self.assertEqual(sat, b_val == (not a_val))

    def test_add_sum_explicit_output(self):
        a = [1, 2, 3, 4]
        b = [5, 6, 7, 8]
        c = [9, 10, 11, 12]
        self.collider._add_constant(a, 0b1110)
        self.collider._add_constant(b, 0b1101)
        self.collider._add_sum(a, b, c)
        sat, model = self.collider.solver.solve()
        self.assertTrue(sat)
        expected = [True, False, True, True]
        for var_id, exp in zip(c, expected):
            self.assertEqual(bool(model[var_id]), exp)
                
    
    def test_add_rotate_left_explicit_output(self):
        a = [1, 2, 3, 4]
        b = [5, 6, 7, 8]
        self.collider._add_rotate_left(a, 2, b)
        self.collider._add_constant(a, 0b1101)
        sat, model = self.collider.solver.solve()
        self.assertTrue(sat)
        expected = [False, True, True, True]
        for var_id, exp in zip(b, expected):
            self.assertEqual(bool(model[var_id]), exp)


    def test_solve_md5_chunk(self):
        string = MD5.md5_padded(b"Hello, World!")
        md5 = MD5()
        true_digest = md5.md5_digest(string)
        self.collider = MD5Collider(string)
        sat, (x, digest) = self.collider.solve_md5()
        self.assertTrue(sat)
        self.assertEqual(x, string)
        self.assertEqual(digest, true_digest)
        
    def test_solve_md5_collision(self):
        
        #m0 = 0x02dd31d1c4eee6c5069a3d695cf9af9887b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780
        #m1 = 0xd11d0b969c7b41dcf497d8e4d555655ac79a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c15cc79ddcb74ed6dd3c55fd80a9bb1e3a7cc35
        
        # m0_prime = 0x02dd31d1c4eee6c5069a3d695cf9af9807b5ca2fab7e46123e580440897ffbb80634ad5502b3f4098388e4835a41f125e82551089fc9cdf772bd1dd95b3c3780
        # m1_prime = 0xd11d0b969c7b41dcf497d8e4d555655a479a73350cfdebf066f129308fb109d1797f2775eb5cd530baade8225c154c79ddcb74ed6dd3c55f580a9bb1e3a7cc35
        
        #m0 = 0x2dd31d1c4eee6c569a3d695cf9af9887b5ca2fab7e46123e580440897ffbb8634ad552b3f4098388e4835a417125e82551089fc9cdf7f2bd1dd95b3c3780
        #m1 = 0xd11d0b969c7b41dcf497d8e4d555655ac79a7335cfdebf066f129308fb109d1797f2775eb5cd530baade8225c15cc79ddcb74ed6dd3c55fd80a9bb1e3a7cc35
        
        m0 = b"TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
        
        def interrupt(s):
            s.interrupt()
        
        true_digest = MD5().md5_digest(m0)
        all_inputs = set()
        found_solution = False
        for i in range(512):
                    exclude_bits = [i]
                    self.collider = MD5Collider(MD5.md5_padded(m0), target_digest=true_digest, exclude_input_bits=exclude_bits)
                    timer = Timer(1, interrupt, [self.collider.solver])
                    timer.start()
                    sat, result = self.collider.solve_md5()
                    if sat:
                        x, digest = result
                        all_inputs.add(str(x))
                        found_solution = True
                        break
        assert found_solution, "No solution found"
        
if __name__ == "__main__":
    unittest.main(verbosity=1)
