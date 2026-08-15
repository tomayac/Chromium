// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_PUBLIC_HASH_LIST_H_
#define CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_PUBLIC_HASH_LIST_H_

#include <stddef.h>
#include <stdint.h>

#include <string_view>
#include <vector>

#include "base/files/file_path.h"
#include "content/common/content_export.h"

namespace content {

class CrossOriginStorageHash;

// The Public Hash List (PHL): the vendor-neutral allowlist that decides whether
// a "*"-scoped COS entry may be disclosed to an origin outside its storing
// origins. https://wicg.github.io/cross-origin-storage/#public-hash-list
//
// Backed by a packed file of sorted, contiguous 32-byte SHA-256 digests shipped
// beside the browser binary, loaded once on first lookup and binary searched
// thereafter.
//
// Only SHA-256 digests are listed upstream, so an entry hashed with any other
// recognized algorithm can never clear this gate; the algorithm is checked
// before a lookup is even attempted.
class CONTENT_EXPORT CrossOriginStoragePublicHashList {
 public:
  CrossOriginStoragePublicHashList();
  CrossOriginStoragePublicHashList(const CrossOriginStoragePublicHashList&) =
      delete;
  CrossOriginStoragePublicHashList& operator=(
      const CrossOriginStoragePublicHashList&) = delete;
  ~CrossOriginStoragePublicHashList();

  // Reads and validates the packed data file. Blocking; run this on a sequence
  // that permits blocking, then hand the result to SetPackedDigests().
  //
  // Fails closed on every error path: an unreadable, missing, or malformed data
  // file yields an empty list, so nothing is disclosable, rather than being
  // treated as "everything is listed".
  static std::vector<uint8_t> LoadFromDisk();

  // Adopts digests produced by LoadFromDisk() (or, in tests, constructed
  // directly). Each record must be exactly 32 bytes.
  void SetPackedDigests(std::vector<uint8_t> packed_digests);

  // Returns whether `hash` is on the current snapshot of the list. Never
  // blocks: it binary searches already-loaded bytes, and returns false if
  // nothing has been loaded.
  bool Contains(const CrossOriginStorageHash& hash) const;

  void SetDigestsForTesting(std::vector<uint8_t> packed_digests) {
    SetPackedDigests(std::move(packed_digests));
  }

  size_t size_for_testing() const;

 private:
  // Resolves to the packed file's location next to the installed binary. This
  // is compiled-application data, not per-user profile state.
  static base::FilePath GetDataFilePath();

  // Sorted, contiguous 32-byte records. Empty when nothing could be loaded.
  std::vector<uint8_t> packed_digests_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_PUBLIC_HASH_LIST_H_
