"""Verify file bytes against an authenticated reference. Independent demonstration tool."""
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in manifest")
        result[key] = value
    return result

def _reject_constant(value):
    raise ValueError("Nonstandard JSON numeric constant")


def calculate_sha256(file_path, chunk_size=1024 * 1024):
    """Calculate a file's SHA-256 hash without changing its contents."""
    if type(chunk_size) is not int or chunk_size <= 0:
        raise ValueError('chunk_size must be a positive integer')
    fingerprint = hashlib.sha256()
    with Path(file_path).open('rb') as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            fingerprint.update(chunk)
    return fingerprint.hexdigest()

def scan_folder(folder):
    """Scan regular files; report failures instead of silently skipping them."""
    root = Path(folder)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Choose an existing folder, not a symbolic link')
    result = {'algorithm': 'SHA-256', 'started_utc': datetime.now(timezone.utc).isoformat(), 'files': {}, 'issues': []}

    def report_issue(path, reason):
        result['issues'].append({'path': str(Path(path).relative_to(root).as_posix()), 'reason': reason})

    def directory_error(error):
        report_issue(error.filename or root, f'Directory could not be read: {type(error).__name__}')
    for current, directories, filenames in os.walk(root, followlinks=False, onerror=directory_error):
        directories.sort()
        for name in directories[:]:
            path = Path(current) / name
            if path.is_symlink():
                report_issue(path, 'Symbolic-link directory excluded')
                directories.remove(name)
        for name in sorted(filenames):
            path = Path(current) / name
            relative_name = path.relative_to(root).as_posix()
            try:
                if path.is_symlink() or not path.is_file():
                    report_issue(path, 'Link or nonregular file excluded')
                    continue
                before = path.stat()
                digest = calculate_sha256(path)
                after = path.stat()

                def signature(info):
                    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if signature(before) != signature(after):
                    report_issue(path, 'File changed during hashing; retry needed')
                    continue
                result['files'][relative_name] = {'sha256': digest, 'size_bytes': after.st_size}
            except OSError as error:
                report_issue(path, f'File could not be read: {type(error).__name__}')
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    result['scan_complete'] = not result['issues']
    return result

def load_verified_manifest(manifest_file, signature_file, public_key_file, expected_fingerprint):
    """Authenticate and validate a manifest before returning its contents."""
    key_bytes = Path(public_key_file).read_bytes()
    actual_fingerprint = hashlib.sha256(key_bytes).hexdigest()
    if not hmac.compare_digest(actual_fingerprint, expected_fingerprint):
        raise ValueError('Verification key does not match the trusted fingerprint')
    key = Ed25519PublicKey.from_public_bytes(key_bytes)
    signed_bytes = Path(manifest_file).read_bytes()
    signature_bytes = Path(signature_file).read_bytes()
    key.verify(signature_bytes, signed_bytes)
    reference = json.loads(signed_bytes, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
    if not isinstance(reference, dict):
        raise ValueError('Manifest must be a JSON object')
    if type(reference.get('schema_version')) is not int or reference['schema_version'] != 1 or reference.get('algorithm') != 'SHA-256':
        raise ValueError('Unsupported manifest version or algorithm')
    entries = reference.get('files')
    if not isinstance(entries, dict) or not entries:
        raise ValueError('Manifest must contain file entries')
    for name, details in entries.items():
        parts = name.split('/')
        if not name or any(ord(c) < 32 for c in name) or PurePosixPath(name).is_absolute() or '\\' in name or (':' in name) or any((part in ('', '.', '..') for part in parts)):
            raise ValueError('Manifest contains an unsafe file path')
        if not isinstance(details, dict):
            raise ValueError('Invalid file entry')
        digest = details.get('sha256')
        size = details.get('size_bytes')
        if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None or type(size) is not int or (size < 0):
            raise ValueError('Invalid fingerprint or file size')
    return reference

def verify_folder(folder, manifest_file, signature_file, public_key_file, expected_fingerprint):
    """Authenticate the reference, scan the folder, and compare files."""
    reference = load_verified_manifest(manifest_file, signature_file, public_key_file, expected_fingerprint)
    current = scan_folder(folder)
    expected_files = reference['files']
    observed_files = current['files']
    comparisons = []
    for name in sorted(set(expected_files) | set(observed_files)):
        expected = expected_files.get(name)
        observed = observed_files.get(name)
        if expected is None:
            status = 'NEW'
        elif observed is None:
            status = 'MISSING' if current['scan_complete'] else 'NOT_VERIFIED'
        elif expected['sha256'] == observed['sha256'] and expected['size_bytes'] == observed['size_bytes']:
            status = 'UNCHANGED'
        else:
            status = 'MODIFIED'
        comparisons.append({'path': name, 'status': status, 'expected_sha256': expected['sha256'] if expected else None, 'observed_sha256': observed['sha256'] if observed else None, 'expected_size': expected['size_bytes'] if expected else None, 'observed_size': observed['size_bytes'] if observed else None})
    if not current['scan_complete']:
        outcome = 'INCOMPLETE'
    elif any((row['status'] != 'UNCHANGED' for row in comparisons)):
        outcome = 'DIFFERENCES_DETECTED'
    else:
        outcome = 'VERIFIED_MATCH'
    return {'reference_authenticated': True, 'verification_key_fingerprint': expected_fingerprint, 'scan_started_utc': current['started_utc'], 'scan_finished_utc': current['finished_utc'], 'outcome': outcome, 'files': comparisons, 'scan_issues': current['issues']}
