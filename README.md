# Digital Evidence Integrity Verifier

**Author: Nnenne Mercy Nwanoruo**

A Python tool that checks whether a folder's files match an authenticated reference. It uses SHA-256 file fingerprints, an Ed25519-signed manifest, and a pinned public-key fingerprint. It reports unchanged, modified, missing, new, and unverified files, and prevents an incomplete scan from producing an overall success.

Designed as an independent demonstration with potential applications across **U.S. law enforcement, courts, prosecutors' offices, and forensic laboratories**. It has no state-specific data dependency. Geographic applicability is a design property; national adoption or operational impact has not been established.

## Problem and intended workflow

When files are stored, copied, or restored, the person receiving them needs a repeatable way to compare them with the recorded originals. A file name or size alone cannot detect every change. This tool fingerprints file bytes and checks the reference's signature before comparison.

1. Establish a reference while the source files are trusted and quiescent.
2. Sign its manifest; keep the private signing key protected separately.
3. Pin the verification key's fingerprint in trusted configuration.
4. Verify a stored or destination folder against that signed reference.
5. Review the outcome, per-file differences, and scan issues.

NIST's [Digital Evidence Preservation: Considerations for Evidence Handlers (IR 8387)](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8387.pdf) discusses evidence hashing and protection of reference hashes. This project implements a related file-verification workflow; it is not NIST-endorsed or a compliance assessment. Signing uses the [cryptography Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

## Run the self-contained notebook

1. Open `Digital_Evidence_Integrity_Verifier.ipynb` in Google Colab.
2. Run cells from top to bottom. If dependencies are missing, install the versions in `requirements.txt` first.
3. Choose a nonempty password when prompted to encrypt the demonstration signing key. Do not enter a real agency key or real evidence into this demo.
4. Review the controlled test outcomes and download the final 11-file report ZIP.

Each full run creates a new isolated demonstration folder and key, so it never overwrites an older reference. Individual manifest/signing-cell reruns reuse and verify the existing reference rather than silently establishing a new baseline. Partial key setup or a missing trusted pin stops the signing cell. To start again, run from the first cell and continue in order.

The notebook contains all required functions; it does not need the module files uploaded to Colab. The publication notebook has cleared outputs to remove stale errors and avoid suggesting that old outputs belong to a new run. Original recorded outputs are preserved separately below.

## Use the verifier locally

Dependencies: Python with `cryptography` and pandas for the notebook/export. Local packaging checks used Python 3.12; the original author-recorded Colab run used Python 3.13. Linux was tested; other operating systems have not been validated.

```bash
python -m pip install -r requirements.txt
python -m unittest -v
```

The reusable functions are in `integrity_verifier.py`. A separate command-line entry point verifies an existing signed reference:

```bash
python verify_cli.py \
  --folder /path/to/destination \
  --manifest /path/to/reference/manifest.json \
  --signature /path/to/reference/manifest.sig \
  --public-key /path/to/trusted/verification_key.pub \
  --expected-fingerprint YOUR_INDEPENDENTLY_TRUSTED_PUBLIC_KEY_SHA256 \
  --report /path/outside/evidence/new_report.json
```

The command does not create keys or establish trust. Provision the expected fingerprint through trusted configuration, not by automatically accepting the key presented alongside an untrusted manifest. The notebook pins its new key during initial demonstration setup.

The command refuses to overwrite an existing report or write it inside the evidence folder. Exit statuses: **0** verified match, **1** differences detected, **2** incomplete scan, **3** verification/reporting stopped. Authentication failures stop before scanning and do not produce a successful report.

## Outcomes

| Outcome/status | Meaning |
| --- | --- |
| `VERIFIED_MATCH` | All referenced files matched; no new files or scan issues were observed |
| `DIFFERENCES_DETECTED` | Completed scan found a modification, missing file, or new file |
| `INCOMPLETE` | A read/traversal problem, excluded item, or observed mutation prevented full verification |
| `NOT_VERIFIED` | A reference entry was not successfully read during an incomplete scan; absence is not assumed |

Paths are relative to the scanned folder. A renamed file appears as missing at the old path and new at the new path. Directories themselves are not evidence entries. Symlinks/nonregular files are excluded and cause an incomplete outcome.

## Evaluation and recorded results

All examples are fictional. The supplied `recorded_results/` files are preserved byte-for-byte from the author's October 21, 2026 Colab export. They report:

| Experiment | Recorded outcome |
| --- | --- |
| Original three-file folder | Three unchanged files; verified match |
| One-byte edit, deleted file, and added file | Modified/missing/new statuses matched the designed scenario |
| Simulated file-read failure | Incomplete scan; affected file not verified |
| Local destination copy | Three unchanged files; verified match |

Original notebook outputs also recorded rejection of an altered manifest, altered signature, and unrelated public key. Fresh references were generated locally to rerun those behaviors; the original signed manifest, signature, and public-key file were not supplied, so the original reports' authentication claims were not independently reverified. Exported reports are unsigned.

Author-recorded hashing benchmark (three timed runs per size; median):

| File size | Median seconds | MiB/second |
| --- | ---: | ---: |
| 1 MiB | 0.0034 | 291.07 |
| 16 MiB | 0.0546 | 293.08 |
| 64 MiB | 0.2161 | 296.18 |

All nine hashes matched expected fingerprints. These are local, cache-sensitive hashing measurements, excluding file generation; they are not whole-workflow, disk-capacity, agency-system, or nationwide performance estimates. Full precision and software versions are in the recorded CSV/JSON files.

Packaging validation passed **13 automated unit tests**, two complete notebook executions, individual reference/signing-cell reruns, and command-line smoke checks. Tests cover known hashes, exact change classifications, rejection before scanning, signature/key changes, duplicate JSON keys, unsafe paths, malformed entries, a simulated read failure, observable mutation during hashing, and symlink exclusion. See `VALIDATION.txt`.

## Trust boundaries and practical scope

- The reference describes file bytes at its creation; it cannot establish their earlier authenticity or identify who changed them. A complete chain of custody requires additional procedures and records.
- Protect the private key, pinned fingerprint, verifier code, and trusted execution environment. A signature alone does not establish the signer's real-world identity. Ed25519 use here is not a claim of FIPS validation or CJIS compliance.
- Scan a quiescent folder. Metadata checks detect some concurrent changes; this is not an atomic snapshot or a defense against an adversary racing filesystem links/contents. Comparison excludes extended attributes, permissions, alternate streams, and other filesystem metadata.
- JSON/CSV reports are unsigned, and clock times are not trusted timestamps. No agency deployment, independent forensic certification, operational validation, or adoption is claimed.

Next work should validate the workflow with independent practitioners, assess operational requirements, and test larger and more varied collections. No measured impact should be inferred from controlled demonstrations alone.

## Repository contents

- `Digital_Evidence_Integrity_Verifier.ipynb`: self-contained demonstration and report export.
- `integrity_verifier.py`: reusable hashing, scanning, authentication, and comparison functions.
- `verify_cli.py`: command-line verification of existing references.
- `test_integrity_verifier.py`: automated fictional tests.
- `recorded_results/`: original 11-file author-recorded export.
- `requirements.txt`, `.gitignore`, `VALIDATION.txt`: dependencies, exclusions, and validation evidence.

Private keys, passwords, and real evidence are not included. The public-key fingerprints appearing in recorded reports are public identifiers, not private keys. Follow the exclusions when publishing future runs.
