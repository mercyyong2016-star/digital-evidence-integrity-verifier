"""Read-only verification against an externally pinned signed reference."""
import argparse
import json
import sys
from pathlib import Path
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from integrity_verifier import verify_folder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--signature', required=True)
    parser.add_argument('--public-key', required=True)
    parser.add_argument('--expected-fingerprint', required=True,
                        help='SHA-256 of the public key, from trusted configuration')
    parser.add_argument('--report', required=True,
                        help='New output JSON path outside the evidence folder')
    args = parser.parse_args()
    try:
        evidence = Path(args.folder).resolve()
        output = Path(args.report).resolve()
        if output == evidence or evidence in output.parents:
            raise ValueError('Report must be outside the evidence folder')
        report = verify_folder(args.folder, args.manifest, args.signature,
                               args.public_key, args.expected_fingerprint)
        with output.open('x', encoding='utf-8') as f:
            json.dump(report, f, indent=2, allow_nan=False)
            f.write('\n')
    except (InvalidSignature, UnsupportedAlgorithm, OSError, ValueError, UnicodeError) as error:
        print(f'Verification stopped: {type(error).__name__}: {error}', file=sys.stderr)
        return 3
    print(report['outcome'])
    return {'VERIFIED_MATCH': 0, 'DIFFERENCES_DETECTED': 1, 'INCOMPLETE': 2}[report['outcome']]


if __name__ == '__main__':
    raise SystemExit(main())
