#!/usr/bin/env python3
# Copyright 2026 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Regenerates the packed Public Hash List (PHL) shipped with Chromium.

The PHL is the availability-gating allowlist that decides whether a
"*"-scoped Cross-Origin Storage entry may be disclosed to an origin that did
not store it. See
https://wicg.github.io/cross-origin-storage/#public-hash-list

Upstream publishes it as a ~58 MB text file of bare lowercase-hex SHA-256
digests, tracked in Git LFS. This script fetches it (via GitHub's LFS media
endpoint, since raw.githubusercontent.com only serves the LFS pointer),
verifies it against the companion .sha256 file published beside it, and
re-encodes the digests as sorted, packed 32-byte binary records with no
delimiters. That form is ~6x smaller than the text and supports an O(log n)
binary search at lookup time without the memory cost of a hash set.

The list is a rolling release, so this needs re-running periodically; a build
is only ever as current as the last time this was run and its output landed.

Usage:
  third_party/cross_origin_storage_public_hash_list/generate_public_hash_list.py

  # Re-pack an already-downloaded copy instead of fetching:
  ... --dat-file /path/to/public-hash-list.dat
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request

# GitHub's LFS media endpoint. raw.githubusercontent.com serves only the LFS
# pointer text for these paths, not the actual content.
_LFS_BASE = ('https://media.githubusercontent.com/media/WICG/'
             'cross-origin-storage/main/public-hash-list/implementation/data')
_DAT_URL = f'{_LFS_BASE}/public-hash-list.dat'
_SHA256_URL = f'{_LFS_BASE}/public-hash-list.dat.sha256'

# The LFS pointer is a few hundred bytes and names the upstream object's OID,
# so --check can tell whether a roll is needed without pulling ~58 MB.
_POINTER_URL = ('https://raw.githubusercontent.com/WICG/cross-origin-storage/'
                'main/public-hash-list/implementation/data/public-hash-list.dat')

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_OUTPUT = os.path.join(_THIS_DIR, 'public_hash_list.bin')
_VERSION_FILE = os.path.join(_THIS_DIR, 'VERSION')
_METADATA_FILE = os.path.join(_THIS_DIR, 'public_hash_list.metadata.json')

_DIGEST_RE = re.compile(r'^[0-9a-f]{64}$')
_SECTION_BEGIN_RE = re.compile(r'^//\s*===BEGIN\s+(.*?)===\s*$')
_SECTION_END_RE = re.compile(r'^//\s*===END\s+(.*?)===\s*$')
_VERSION_RE = re.compile(r'^//\s*VERSION:\s*(.*?)\s*$')

# Which sections of the upstream file this implementation adopts.
#
# "SHA-256" is the core section: corroborated by real-world popularity, and a
# user agent MUST treat it as eligible. "SHA-256 MANUAL" is hand-curated
# against the same ubiquity bar and is likewise a MUST.
#
# "SHA-256 HUGGING-FACE" qualifies entries on a different basis -- published on
# a recognized model hub rather than measured ubiquity -- and a user agent
# SHOULD include it but MAY omit it. We include it deliberately: omitting it
# would force large model downloads to repeat per origin, and uneven adoption
# across vendors is exactly what the PHL exists to avoid.
_ADOPTED_SECTIONS = frozenset(
    ['SHA-256', 'SHA-256 MANUAL', 'SHA-256 HUGGING-FACE'])


def _fetch(url):
  print(f'Fetching {url}', file=sys.stderr)
  with urllib.request.urlopen(url) as response:
    return response.read()


def _fetch_upstream_oid():
  """Returns the OID from upstream's Git LFS pointer, or None.

  The pointer looks like:
      version https://git-lfs.github.com/spec/v1
      oid sha256:<64 hex>
      size <bytes>
  """
  pointer = _fetch(_POINTER_URL).decode('utf-8', errors='replace')
  match = re.search(r'^oid sha256:([0-9a-f]{64})$', pointer, re.M)
  return match.group(1) if match else None


def _read_committed_metadata():
  try:
    with open(_METADATA_FILE) as f:
      return json.load(f)
  except (OSError, ValueError):
    return {}


def _check_for_updates():
  """Exit 0 if the committed list is current, 1 if a roll is needed.

  Cheap by design: it compares OIDs from the LFS pointer rather than
  downloading the list, so a scheduled job can run it often.
  """
  upstream_oid = _fetch_upstream_oid()
  if not upstream_oid:
    print('Could not read the upstream LFS pointer; treating as unknown.',
          file=sys.stderr)
    return 2

  committed_oid = _read_committed_metadata().get('upstream_oid')
  if committed_oid == upstream_oid:
    print(f'Up to date (upstream oid {upstream_oid}).', file=sys.stderr)
    return 0

  print(
      f'Roll needed.\n  committed: {committed_oid}\n  upstream:  {upstream_oid}',
      file=sys.stderr)
  return 1


def _download_and_verify():
  """Returns the .dat contents, verified against the published checksum.

  The checksum is fetched first and the data pinned against it, so a corrupted
  or truncated transfer becomes a loud failure here rather than silently-wrong
  data compiled into every user's browser.
  """
  checksum_line = _fetch(_SHA256_URL).decode('ascii').strip()
  expected = checksum_line.split()[0]
  if not _DIGEST_RE.match(expected):
    raise ValueError(f'Malformed checksum file contents: {checksum_line!r}')

  data = _fetch(_DAT_URL)
  actual = hashlib.sha256(data).hexdigest()
  if actual != expected:
    raise ValueError(
        f'Checksum mismatch for public-hash-list.dat: expected {expected}, '
        f'got {actual}. Refusing to generate from unverified data.')
  print(f'Verified public-hash-list.dat ({len(data)} bytes) against {expected}',
        file=sys.stderr)
  return data


def _parse(text):
  """Yields (digests, version, per_section_counts) for the adopted sections."""
  digests = set()
  counts = {}
  version = None
  section = None

  for line in text.splitlines():
    line = line.strip()
    if not line:
      continue
    if line.startswith('//'):
      begin = _SECTION_BEGIN_RE.match(line)
      if begin:
        section = begin.group(1).strip()
        counts.setdefault(section, 0)
        continue
      if _SECTION_END_RE.match(line):
        section = None
        continue
      found_version = _VERSION_RE.match(line)
      if found_version and version is None:
        version = found_version.group(1)
      # Every other comment line carries provenance only, and is ignored.
      continue

    if section is None:
      raise ValueError(f'Digest line outside any section: {line!r}')
    if not _DIGEST_RE.match(line):
      raise ValueError(f'Malformed digest line: {line!r}')
    counts[section] = counts[section] + 1
    if section in _ADOPTED_SECTIONS:
      digests.add(line)

  unknown = set(counts) - _ADOPTED_SECTIONS
  if unknown:
    # A new upstream section is a deliberate adoption decision, not something
    # to silently fold in or silently drop.
    raise ValueError(
        f'Unrecognized section(s) {sorted(unknown)} in the upstream list. '
        'Decide explicitly whether to adopt them and update '
        '_ADOPTED_SECTIONS.')

  return digests, version, counts


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
      '--dat-file',
      help='Re-pack this local copy instead of downloading. Skips checksum '
      'verification, so only use it with a file this script downloaded.')
  parser.add_argument('--output', default=_OUTPUT)
  parser.add_argument(
      '--check',
      action='store_true',
      help='Do not regenerate anything. Exit 0 if the committed list matches '
      'upstream, 1 if a roll is needed, 2 if that could not be determined. '
      'This is what a scheduled job should run.')
  args = parser.parse_args()

  if args.check:
    return _check_for_updates()

  upstream_oid = None
  if args.dat_file:
    with open(args.dat_file, 'rb') as f:
      data = f.read()
    upstream_oid = hashlib.sha256(data).hexdigest()
  else:
    data = _download_and_verify()
    upstream_oid = hashlib.sha256(data).hexdigest()

  digests, version, counts = _parse(data.decode('utf-8'))

  for section in sorted(counts):
    adopted = 'adopted' if section in _ADOPTED_SECTIONS else 'SKIPPED'
    print(f'  {section}: {counts[section]} digests ({adopted})',
          file=sys.stderr)

  # Sorted once, here, so nothing has to re-sort at process startup and the
  # browser can binary search the packed bytes directly.
  packed = b''.join(bytes.fromhex(d) for d in sorted(digests))
  with open(args.output, 'wb') as f:
    f.write(packed)

  with open(_VERSION_FILE, 'w') as f:
    f.write(f'{version or "unknown"}\n')

  # Recorded so --check can decide whether a roll is needed from the LFS
  # pointer alone, without downloading the list.
  metadata = {
      'upstream_version': version,
      'upstream_oid': upstream_oid,
      'packed_sha256': hashlib.sha256(packed).hexdigest(),
      'digest_count': len(digests),
      'adopted_sections': sorted(_ADOPTED_SECTIONS),
      'section_counts': counts,
  }
  with open(_METADATA_FILE, 'w') as f:
    json.dump(metadata, f, indent=2, sort_keys=True)
    f.write('\n')

  print(
      f'Wrote {args.output}: {len(digests)} digests, {len(packed)} bytes '
      f'(upstream version {version})',
      file=sys.stderr)
  return 0


if __name__ == '__main__':
  sys.exit(main())
