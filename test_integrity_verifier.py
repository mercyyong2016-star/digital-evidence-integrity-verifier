"""Controlled fictional tests; no real evidence or permanent private keys."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import integrity_verifier as verifier


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / 'evidence'
        (self.evidence / 'nested').mkdir(parents=True)
        (self.evidence / 'a.txt').write_bytes(b'abc')
        (self.evidence / 'nested/b.bin').write_bytes(bytes(range(256)))
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public = self.root / 'public.pub'
        self.public.write_bytes(public)
        self.pin = hashlib.sha256(public).hexdigest()
        self.manifest = self.root / 'manifest.json'
        self.signature = self.root / 'manifest.sig'
        scan = verifier.scan_folder(self.evidence)
        self.reference = {'schema_version': 1, 'algorithm': 'SHA-256', 'files': scan['files']}
        self.sign(self.reference)

    def sign(self, reference):
        data = json.dumps(reference).encode()
        self.manifest.write_bytes(data)
        self.signature.write_bytes(self.key.sign(data))

    def verify(self):
        return verifier.verify_folder(self.evidence, self.manifest, self.signature, self.public, self.pin)

    def test_unchanged_and_known_hash(self):
        self.assertEqual(verifier.calculate_sha256(self.evidence / 'a.txt', 1),
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        report = self.verify()
        self.assertEqual(report['outcome'], 'VERIFIED_MATCH')
        self.assertEqual([r['status'] for r in report['files']], ['UNCHANGED', 'UNCHANGED'])

    def test_same_size_edit_missing_and_new(self):
        (self.evidence / 'a.txt').write_bytes(b'abd')
        (self.evidence / 'nested/b.bin').unlink()
        (self.evidence / 'new.txt').write_bytes(b'new')
        report = self.verify()
        self.assertEqual(report['outcome'], 'DIFFERENCES_DETECTED')
        self.assertEqual({r['path']: r['status'] for r in report['files']},
                         {'a.txt': 'MODIFIED', 'nested/b.bin': 'MISSING', 'new.txt': 'NEW'})

    def test_altered_manifest_rejected_before_scan(self):
        self.manifest.write_bytes(self.manifest.read_bytes() + b' ')
        with patch.object(verifier, 'scan_folder') as scanner:
            with self.assertRaises(InvalidSignature):
                self.verify()
            scanner.assert_not_called()

    def test_altered_signature(self):
        data = bytearray(self.signature.read_bytes())
        data[0] ^= 1
        self.signature.write_bytes(data)
        with self.assertRaises(InvalidSignature):
            self.verify()

    def test_replaced_public_key(self):
        replacement = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public.write_bytes(replacement)
        with self.assertRaisesRegex(ValueError, 'trusted fingerprint'):
            self.verify()

    def test_other_signer_cannot_use_trusted_key(self):
        self.signature.write_bytes(Ed25519PrivateKey.generate().sign(self.manifest.read_bytes()))
        with self.assertRaises(InvalidSignature):
            self.verify()

    def test_duplicate_json_keys_rejected(self):
        raw = b'{"schema_version":1,"schema_version":1,"algorithm":"SHA-256","files":{}}'
        self.manifest.write_bytes(raw)
        self.signature.write_bytes(self.key.sign(raw))
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
            self.verify()

    def test_unsafe_paths_rejected(self):
        detail = next(iter(self.reference['files'].values()))
        for path in ['../outside', '/absolute', 'a//b', 'a/./b', 'a\\b', 'C:file', 'a\x00b']:
            with self.subTest(path=repr(path)):
                self.reference['files'] = {path: detail}
                self.sign(self.reference)
                with self.assertRaisesRegex(ValueError, 'unsafe file path'):
                    self.verify()

    def test_invalid_digest_and_boolean_size(self):
        for detail in [{'sha256': 'bad', 'size_bytes': 3},
                       {'sha256': 'a' * 64, 'size_bytes': True}]:
            with self.subTest(detail=detail):
                self.reference['files'] = {'a.txt': detail}
                self.sign(self.reference)
                with self.assertRaisesRegex(ValueError, 'fingerprint or file size'):
                    self.verify()

    def test_read_failure_is_incomplete(self):
        real_hash = verifier.calculate_sha256
        def blocked(path, chunk_size=1024*1024):
            if Path(path).name == 'a.txt':
                raise PermissionError('Controlled test')
            return real_hash(path, chunk_size)
        with patch.object(verifier, 'calculate_sha256', side_effect=blocked):
            report = self.verify()
        self.assertEqual(report['outcome'], 'INCOMPLETE')
        self.assertEqual(report['files'][0]['status'], 'NOT_VERIFIED')
        self.assertIn('PermissionError', report['scan_issues'][0]['reason'])

    def test_observable_mutation_during_hashing(self):
        real_hash = verifier.calculate_sha256
        def changed(path, chunk_size=1024*1024):
            digest = real_hash(path, chunk_size)
            if Path(path).name == 'a.txt':
                with Path(path).open('ab') as f:
                    f.write(b'changed')
            return digest
        with patch.object(verifier, 'calculate_sha256', side_effect=changed):
            report = self.verify()
        self.assertEqual(report['outcome'], 'INCOMPLETE')
        self.assertTrue(any('changed during hashing' in r['reason'] for r in report['scan_issues']))

    def test_symlink_is_excluded_and_not_success(self):
        link = self.evidence / 'linked.txt'
        try:
            link.symlink_to(self.evidence / 'a.txt')
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks unavailable on this platform')
        report = self.verify()
        self.assertEqual(report['outcome'], 'INCOMPLETE')
        self.assertTrue(any(r['path'] == 'linked.txt' for r in report['scan_issues']))

    def test_chunk_size_rejected(self):
        for size in [0, -1, True, 1.5]:
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    verifier.calculate_sha256(self.evidence / 'a.txt', size)


if __name__ == '__main__':
    unittest.main()
