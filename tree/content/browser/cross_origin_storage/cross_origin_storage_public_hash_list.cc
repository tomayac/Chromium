// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_public_hash_list.h"

#include <algorithm>
#include <array>

#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_types.h"

namespace content {

namespace {

// Every record is a raw SHA-256 digest.
constexpr size_t kDigestBytes = 32;

constexpr base::FilePath::CharType kDataFileName[] =
    FILE_PATH_LITERAL("cross_origin_storage_public_hash_list.bin");

// Guards against a corrupted or hostile data file claiming an implausible
// size. The real list is ~9.5 MiB; a rolling release can grow, but not by
// orders of magnitude between updates.
constexpr size_t kMaxDataFileBytes = 256u * 1024 * 1024;

}  // namespace

CrossOriginStoragePublicHashList::CrossOriginStoragePublicHashList() = default;
CrossOriginStoragePublicHashList::~CrossOriginStoragePublicHashList() = default;

// static
base::FilePath CrossOriginStoragePublicHashList::GetDataFilePath() {
  base::FilePath dir;
  if (!base::PathService::Get(base::DIR_ASSETS, &dir)) {
    return base::FilePath();
  }
  return dir.Append(kDataFileName);
}

// static
std::vector<uint8_t> CrossOriginStoragePublicHashList::LoadFromDisk() {
  const base::FilePath path = GetDataFilePath();
  if (path.empty()) {
    LOG(WARNING) << "Cross-Origin Storage: could not resolve the Public Hash "
                    "List path; no hash will be treated as listed.";
    return {};
  }

  // Checked before reading, so a corrupted or hostile data file claiming an
  // implausible size cannot be pulled into memory in the first place. The real
  // list is ~9.5 MiB; a rolling release grows, but not by orders of magnitude.
  std::optional<int64_t> size = base::GetFileSize(path);
  if (!size || *size < 0 || static_cast<uint64_t>(*size) > kMaxDataFileBytes) {
    LOG(WARNING) << "Cross-Origin Storage: the Public Hash List at " << path
                 << " is missing or implausibly sized; no hash will be treated "
                 << "as listed.";
    return {};
  }

  std::optional<std::vector<uint8_t>> contents = base::ReadFileToBytes(path);
  if (!contents) {
    LOG(WARNING) << "Cross-Origin Storage: could not read the Public Hash List "
                 << "at " << path << "; no hash will be treated as listed.";
    return {};
  }
  if (contents->size() % kDigestBytes != 0) {
    LOG(ERROR) << "Cross-Origin Storage: the Public Hash List at " << path
               << " is not a whole number of 32-byte digests ("
               << contents->size()
               << " bytes); no hash will be treated as listed.";
    return {};
  }

  VLOG(1) << "Cross-Origin Storage: loaded " << contents->size() / kDigestBytes
          << " Public Hash List digests.";
  return std::move(*contents);
}

void CrossOriginStoragePublicHashList::SetPackedDigests(
    std::vector<uint8_t> packed_digests) {
  CHECK_EQ(packed_digests.size() % kDigestBytes, 0u);
  packed_digests_ = std::move(packed_digests);
}

bool CrossOriginStoragePublicHashList::Contains(
    const CrossOriginStorageHash& hash) const {
  // The upstream list carries SHA-256 digests only, so nothing else can ever be
  // on it. Checking here avoids a pointless load and search.
  if (hash.algorithm() != "SHA-256") {
    return false;
  }

  std::array<uint8_t, kDigestBytes> target;
  if (!base::HexStringToSpan(hash.value(), target)) {
    return false;
  }

  const size_t count = packed_digests_.size() / kDigestBytes;
  if (count == 0) {
    return false;
  }

  // Binary search over the packed records. They were sorted at generation time
  // precisely so this needs no per-startup work and no hash set.
  size_t low = 0;
  size_t high = count;
  while (low < high) {
    const size_t mid = low + (high - low) / 2;
    const auto record =
        base::span(packed_digests_).subspan(mid * kDigestBytes, kDigestBytes);
    const auto ordering =
        std::lexicographical_compare_three_way(record.begin(), record.end(),
                                               target.begin(), target.end());
    if (ordering == std::strong_ordering::equal) {
      return true;
    }
    if (ordering == std::strong_ordering::less) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  return false;
}

size_t CrossOriginStoragePublicHashList::size_for_testing() const {
  return packed_digests_.size() / kDigestBytes;
}

}  // namespace content
