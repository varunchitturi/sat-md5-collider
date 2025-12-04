### Theory Document — MD5, SAT Encodings, and Collision Experiments

### Background and main ideas from the literature

MD5 is a Merkle–Damgård based hash function that maintains a 128-bit internal state `(a, b, c, d)` and processes messages in 512-bit blocks across 64 steps organized into four rounds. Each step mixes the state with: (1) a round-dependent boolean function over `(b, c, d)`, (2) a 32-bit message word, (3) a sine-derived constant, and (4) a bit rotation, followed by state shuffling. This structure is simple, fast, and highly parallel at the bit level—properties that also make it amenable to SAT/CP encodings.

Different cryptological work in the past years developed differential paths and “message modification” techniques to craft MD5 collisions dramatically faster than brute force. The core idea is to track and enforce a sequence of bitwise difference constraints across the 64 steps so that the differences cancel at the feed-forward, yielding identical final states for two distinct messages. Later advances strengthened these techniques to practical chosen-prefix collisions, enabling attacks such as forged X.509 certificates. Over time, researchers have also explored single-block and shortened-collision forms, as well as automated search pipelines to discover high-probability differential characteristics.

In parallel, the SAT/CP community showed that bit-wise cryptographic primitives can be modeled as Boolean circuits and compiled to CNF via Tseitin transformation. Bitwise gates (AND/OR/XOR/NOT), addition (ripple-carry adders), and rotations can be encoded with small clause sets. This enables exact, constraint-driven search for preimages, near-collisions, and, for reduced-round variants, even full collisions—serving both as a verification tool and as a way to prototype cryptanalytic constraints without hand-crafting inputs. These methods, however, face steep complexity growth: each additional round compounds constraints and auxiliary variables, and real-world collision searches typically require domain-specific constraints (e.g., differential conditions) to be tractable.

### Relevance to our project

In this project, we encoded the MD5 compression function as a SAT instance. We model all state bits, message bits, boolean functions, modular additions, and rotates as a CNF formula using Tseitin variables. A PySAT solver searches for satisfying assignments consistent with either a fixed input (to “compute” the digest by SAT), a fixed output (to explore inversion), or selectively unconstrained/perturbed input bits (to illustrate constrained collision-style searches). A reference MD5 implementation is used to validate the SAT-derived results end-to-end on padded inputs.

### Questions, hypotheses, and findings

- Question 1: Can a SAT model reproduce MD5 digests end-to-end (on padded inputs) exactly?
  Hypothesis: Yes—if the bit-precise circuit and endianness are encoded correctly, constraining the input bytes should force the solver to reproduce the reference digest when we read back `(a‖b‖c‖d)` from the model.
  Outcome: Supported. With the input fixed to a padded message, the SAT instance is satisfiable and the recovered digest matches the reference implementation bit-for-bit. This validates the gate encodings (AND/OR/XOR/NOT), the ripple-carry adders, rotate-left wiring, per-round message scheduling, constants, and the final feed-forward addition.

- Question 2: How do reduced rounds impact SAT solvability and runtime? (In terms of inverting a hash)
  Hypothesis: 1–2 rounds should be easy; 3–4 rounds grow substantially harder because additions and carries create long dependencies and rotations spread constraints broadly.
  Outcome: Mostly supported. 1-round encodings solve quickly, but after that. the pipeline increases variable counts and clause interactions, making search slower and more memory-intensive.

- Question 4: Is encoding a full collision (two distinct messages leading to the same digest) straightforward in SAT?
  Hypothesis: Conceptually yes, duplicate the pipeline for two messages, tie the final states `(a, b, c, d)` together with equalities, and include constraints to ensure messages differ.
  Outcome: Not Supported. A two-message CNF doubles the circuit size (plus equality constraints), and naive search is intractable for full MD5. Practical collision SAT models typically incorporate cryptanalytic structure (e.g., difference propagation constraints, stepwise conditions) and solver engineering (assumptions, restarts) to prune the search space. Due to its difficulty we weren't able to encode the constrained search to find collisions (as given in the papers) and leave it as future work.

### Implications

- Cryptanalytic significance: The body of work on MD5 collisions demonstrates that differential structures can be exploited to break collision resistance in practice. Chosen-prefix collisions particularly highlight real-world risks (e.g., certificate forgery). While MD5 is long deprecated, the methodology informs modern analysis of hash designs and differential search.
- Methodological value of SAT/CP: Exact SAT models of cryptographic functions serve as ground truth for bit-level reasoning, regression tests for encodings, and a platform to prototype constraints. They also can help researchers verify the strength/security of different subparts of cryptographic functions.
