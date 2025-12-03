# MD5 SAT Collider (Python + PySAT)

This project encodes the MD5 compression function as a SAT problem and uses a modern SAT solver to:
- Compute an MD5 digest via SAT (end-to-end, on padded input)
- Solve a single 512‑bit MD5 chunk after a single MD5 round
- Illustrate a constrained collision search (time-limited)

Core files:
- `collider.py`: CNF builder around MD5, implemented with logic-gate primitives and a SAT solver.
- `md5.py`: Reference MD5 implementation (used for verification).
- `demo.ipynb`: Notebook demonstrating typical usage (chunk solve, full digest via SAT, collision setup).
- `tests/collider_tests.py`: Unit tests exercising the gate encodings and the MD5 pipeline.


## Installation

Requirements:
- Python 3.8+ (recommended)
- `python-sat` (PySAT, provides Glucose4 solver bindings)
- Optional: Jupyter for running the demo notebook

## Quick Start

Run the notebook demo:

```bash
# From the Project directory
jupyter notebook demo.ipynb
```

Run the tests:

```bash
# From the Project directory
python -m unittest -v tests/collider_tests.py
```


## How the SAT solver works (Tseitin encoding)

At a high level, we model the entire MD5 compression pipeline as a Boolean circuit, then encode that circuit into CNF using Tseitin transformation. The SAT solver then finds an assignment to all circuit variables that satisfies the CNF. From the satisfying assignment (model), we read back the input bytes `x` and the output digest `(a‖b‖c‖d)`.

- **Boolean variables**
  - Every bit of the MD5 state registers `a`, `b`, `c`, `d` (32 bits each) and the input block `x` (512 bits per chunk) is a distinct SAT variable.
  - Additional auxiliary variables are introduced for intermediate gate outputs (Tseitin variables).

- **Tseitin transformation for gates** (representative encodings used in `collider.py`)
  - NOT: `b = ¬a`
    - Clauses: `(¬a ∨ ¬b) ∧ (a ∨ b)`
  - OR: `c = a ∨ b`
    - Clauses: `(a ∨ b ∨ ¬c) ∧ (¬a ∨ c) ∧ (¬b ∨ c)`
  - AND: `c = a ∧ b`
    - Clauses: `(¬a ∨ ¬b ∨ c) ∧ (a ∨ ¬c) ∧ (b ∨ ¬c)`
  - XOR: `c = a ⊕ b`
    - Clauses: `(¬a ∨ ¬b ∨ ¬c) ∧ (a ∨ b ∨ ¬c) ∧ (a ∨ ¬b ∨ c) ∧ (¬a ∨ b ∨ c)`

- **32‑bit addition**
  - Implemented as a ripple-carry adder using XOR/AND/OR gates.
  - The sum bit is XOR over inputs and incoming carry; the carry-out is produced by OR of the pairwise ANDs.

- **Rotate-left**
  - A rotate-left by `n` over 32 bits is encoded as a collection of equalities mapping each source bit to its rotated destination bit.
  - Each bit equality is two clauses (implications) to enforce equivalence.

- **Endianness and message schedule**
  - Byte/word reordering is modeled by wiring (variable mapping), not by arithmetic.
  - The MD5 per-round message index schedule is applied when selecting which word of `x` feeds each round.

- **MD5 round function F**
  - The piecewise function `F(b,c,d,i)` is built from the encoded gates (AND/OR/XOR/NOT), matching the four MD5 phases across 64 steps.
  - Each step computes `b + ROT(a + F + X[i] + K(i), S(i))`, where `+` is 32‑bit addition built from the adder circuit.

- **Constants and known inputs**
  - Known constants (IV and per-round `K(i)`) are fixed with unit clauses.
  - Input bytes are fixed bit-by-bit with unit clauses; selected bits can be left free via `exclude_input_bits` to enable search.

- **Constraining outputs (target digest)**
  - Optionally, the final `(a,b,c,d)` words are constrained to match a given digest using unit clauses on the state bits (after proper endianness conversion).

- **Solving and decoding**
  - The CNF is handed to a Glucose4 solver via PySAT. For long runs, the limited/interrupt API is used to cap time.
  - The returned model is decoded back into bytes for `x` and into a 128‑bit integer digest `(a‖b‖c‖d)`.

This approach yields a single, large SAT instance representing the entire MD5 pipeline. By freeing selected input bits and/or pinning the output digest, you can perform tasks like inversion or constrained collision search within the SAT framework.
