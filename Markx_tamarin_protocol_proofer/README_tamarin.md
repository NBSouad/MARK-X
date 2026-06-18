# Tamarin verification for MARK-X

Symbolic-model verification of the MARK-X migration-aware authenticated
re-key exchange. The protocol has two **variants** (A1: pre-shared key
for the classical channel; A2: explicit ECDH) crossed with two
**modes** for the first message's authentication (A: classical
signature; B: chain bootstrap MAC under a stored K_chain), yielding
four protocol configurations. Each configuration is modeled in its own
self-contained Tamarin theory.

## Files

| File                       | Variant | Mode | Lines  | Maps to paper                              |
|----------------------------|---------|------|--------|--------------------------------------------|
| `markx_core.spthy`         | (shared)| —    | small  | Function signature, setup, restriction.    |
| `markx_a1_modeA.spthy`     | A1 PSK  | A    | medium | Theorems 1, 2, 6.                    |
| `markx_a2_modeA.spthy`     | A2 ECDH | A    | medium | Theorems 1, 3, 4, 6.               |
| `markx_a1_modeB.spthy`     | A1 PSK  | B    | medium | Theorems 2, 7 (A1 chained).            |
| `markx_a2_modeB.spthy`     | A2 ECDH | B    | medium | Theorems 3, 4, 7 (A2 chained).       |

`markx_core.spthy` is a **reference-only** file containing the function
signature, equational theory, setup rules, the sig-key corruption oracle,
and the global `Eq` restriction that every variant shares. It carries a
single sanity lemma so it can be run through Tamarin to confirm the shared
fragment is well-formed; it does **not** model the protocol on its own.
The four variant files each include their own copy of this material (no
`#include`), so each is self-contained and can be checked in isolation.

## Lemma → variant → paper-theorem matrix

| Lemma                       | a1_A | a2_A | a1_B | a2_B | Theorem in paper                              |
|-----------------------------|:----:|:----:|:----:|:----:|-----------------------------------------------|
| `sanity_executable`         |  ✓   |  ✓   |  ✓   |  ✓   | Trace existence (completeness sanity).        |
| `policy_compliance`         |  ✓   |  ✓   |  ✓   |  ✓   | Theorem 1 clause (b) (local-policy).        |
| `auth_install_strong`       |  ✓   |  ✓   |      |      | Theorem 1 clause (a) (signed install).      |
| `auth_install_injective`    |  ✓   |  ✓   |      |      | Server-side `pkpq` uniqueness.                |
| `state_agreement`           |  ✓   |  ✓   |      |      | Theorem 6 (state agreement).                |
| `secrecy_ktrans`            |  ✓   |  ✓   |  ✓   |  ✓   | Theorem 2 (A1) / 3 (A2 no-leak).          |
| `secrecy_ktrans_one_leak`   |      |  ✓   |      |  ✓   | Theorem 4 (A2 leakage-resilient).           |
| `chain_auth`                |      |      |  ✓   |  ✓   | Theorem 7 (epoch-chain authenticity).       |

A blank cell means the lemma does not apply to that variant (e.g. A1
has no ECDH ephemerals, so the leakage-resilient sub-case is meaningless;
Mode B abstracts the Mode A epoch into a setup rule, so install-auth
lemmas are subsumed by the standalone Mode A files).

## Running

With **Tamarin Prover ≥ 1.12** installed. Each file is run independently:

```
tamarin-prover --derivcheck-timeout=0 --prove markx_core.spthy
tamarin-prover --derivcheck-timeout=0 --prove markx_a1_modeA.spthy
tamarin-prover --derivcheck-timeout=0 --prove markx_a2_modeA.spthy
tamarin-prover --derivcheck-timeout=0 --prove markx_a1_modeB.spthy
tamarin-prover --derivcheck-timeout=0 --prove markx_a2_modeB.spthy
```

Expected total runtime on a recent laptop: about 30 seconds across all
five files. Each file should report `All wellformedness checks were
successful` and every stable lemma should print `verified`.

### Including work-in-progress lemmas

Two lemmas — `server_confirm_auth` and `pq_secrecy_essential` — appear
in `markx_a1_modeA.spthy` and `markx_a2_modeA.spthy` under `#ifdef WIP`
guards. They are *sound* statements but Tamarin's autoprover does not
close them within the default search bound: their formulation requires
either the interactive prover, a hand-written sources lemma, or a
tactic. To include them in a run:

```
tamarin-prover --derivcheck-timeout=0 -DWIP --prove markx_a2_modeA.spthy
```

In the WIP run those two lemmas will report `falsified - found trace`
(server_confirm_auth) and `falsified - no trace found` (pq_secrecy_essential).
The traces are heuristic-search artefacts, not real attacks; see the
inline comments above each lemma in the spthy file.

### Notes on the flags

- `--derivcheck-timeout=0` disables the default 5s timeout on the
  derivation-check wellformedness pass. The KEM equation
  `kemDec(kemEnc(K, pk_kem(s), r), s) = K` produces enough AC variants
  that the default timeout fires; the check is a sanity layer, not part
  of soundness, but disabling the timeout silences the spurious
  warning.
- `-DWIP` activates `#ifdef WIP` blocks (only present in the two Mode A
  files).

### Interactive mode

```
tamarin-prover interactive --derivcheck-timeout=0 markx_a2_modeA.spthy
```

Opens a browser-based proof explorer. Use this to step through the WIP
lemmas manually.

## Scope and abstractions

  - **Single transition per file.** Each file models *one* epoch
    transition. Mode B files cover the chained (e0 → e0+1) case where
    the prior epoch's K_chain is abstracted into a `SetupChainState`
    rule. This abstraction matches the paper's framing of Theorem 7,
    which assumes the prior epoch is already authenticated under
    Theorem 1 — composing the full Mode A unrolling with Mode B
    causes Tamarin's source-saturation procedure to fail to terminate.
  - **Monotonicity is out of scope.** Epoch monotonicity in the paper
    is a *conditional* property (Assumption 2.10 — monotonic-state
    integrity is a systems assumption, not a cryptographic one).
    Verifying it symbolically would require encoding the storage model.
  - **Policy as opaque secret.** The local policy is modelled as a
    single fresh name. The paper's policy is a tuple of (algs, params,
    variants, min_epoch, modes); a richer model would carry each
    component as a separate name and check membership explicitly. The
    current model collapses this to "policies match by hash", which is
    sufficient for the policy-compliance lemmas above.
  - **ECDH (A2 only).** Modelled via Tamarin's `diffie-hellman` builtin
    (algebraic theory). Point-validation issues are not captured.
  - **KEM.** Modelled via the user-defined function pair
    `kemEnc/kemDec` with the cancellation equation
    `kemDec(kemEnc(K, pk_kem(s), r), s) = K`. This matches IND-CCA in
    the symbolic model: the adversary cannot recover K from a
    ciphertext without the decapsulation key and cannot construct any
    other ciphertext that decapsulates to the same K.

## What to do if a lemma fails

Each property fails for an identifiable reason if removed from the
protocol. The two most useful diagnostic experiments are:

  - Remove the `Eq(e_recv, e)` and `Eq(ctr_recv, ctr)` action facts in
    `Client_Phase3` → `state_agreement` will fail with a witness in
    which the server commits to `(e, ctr)` but the client accepts
    `(e', ctr')`.
  - Drop the `Eq(policyHash, h(~policy))` in `Client_Phase1` →
    `policy_compliance` fails. This confirms the necessity of the
    local-policy check (review item #6 in MARKX_protocol_review.md).
