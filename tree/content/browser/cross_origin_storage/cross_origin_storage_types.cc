// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_types.h"

#include <algorithm>

#include "base/strings/string_util.h"

namespace content {

namespace {

// The canonical name and hex digest length of each hash algorithm recognized by
// the Web Crypto API. Returns nullptr for anything else.
// https://w3c.github.io/webcrypto/
struct RecognizedAlgorithm {
  const char* canonical_name;
  size_t hex_digest_length;
};

const RecognizedAlgorithm* LookupAlgorithm(std::string_view algorithm) {
  static constexpr RecognizedAlgorithm kAlgorithms[] = {
      {"SHA-1", 40},
      {"SHA-256", 64},
      {"SHA-384", 96},
      {"SHA-512", 128},
  };
  for (const auto& candidate : kAlgorithms) {
    if (base::EqualsCaseInsensitiveASCII(algorithm, candidate.canonical_name)) {
      return &candidate;
    }
  }
  return nullptr;
}

bool IsLowercaseHex(std::string_view value) {
  return std::ranges::all_of(value, [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}

}  // namespace

// static
std::optional<CrossOriginStorageHash> CrossOriginStorageHash::Create(
    std::string_view algorithm,
    std::string_view value) {
  const RecognizedAlgorithm* recognized = LookupAlgorithm(algorithm);
  if (!recognized) {
    return std::nullopt;
  }
  if (value.size() != recognized->hex_digest_length || !IsLowercaseHex(value)) {
    return std::nullopt;
  }
  return CrossOriginStorageHash(recognized->canonical_name, std::string(value));
}

CrossOriginStorageHash::CrossOriginStorageHash(std::string algorithm,
                                               std::string value)
    : algorithm_(std::move(algorithm)), value_(std::move(value)) {}

CrossOriginStorageHash::CrossOriginStorageHash(const CrossOriginStorageHash&) =
    default;
CrossOriginStorageHash& CrossOriginStorageHash::operator=(
    const CrossOriginStorageHash&) = default;
CrossOriginStorageHash::~CrossOriginStorageHash() = default;

CrossOriginStorageProvenanceRecord::CrossOriginStorageProvenanceRecord() =
    default;
CrossOriginStorageProvenanceRecord::CrossOriginStorageProvenanceRecord(
    url::Origin origin,
    GURL source_url,
    base::Time recorded_at)
    : origin(std::move(origin)),
      source_url(std::move(source_url)),
      recorded_at(recorded_at) {}
CrossOriginStorageProvenanceRecord::CrossOriginStorageProvenanceRecord(
    const CrossOriginStorageProvenanceRecord&) = default;
CrossOriginStorageProvenanceRecord&
CrossOriginStorageProvenanceRecord::operator=(
    const CrossOriginStorageProvenanceRecord&) = default;
CrossOriginStorageProvenanceRecord::~CrossOriginStorageProvenanceRecord() =
    default;

CrossOriginStorageEntry::CrossOriginStorageEntry(CrossOriginStorageHash hash)
    : hash(std::move(hash)) {}
CrossOriginStorageEntry::CrossOriginStorageEntry(CrossOriginStorageEntry&&) =
    default;
CrossOriginStorageEntry& CrossOriginStorageEntry::operator=(
    CrossOriginStorageEntry&&) = default;
CrossOriginStorageEntry::~CrossOriginStorageEntry() = default;

bool CrossOriginStorageEntry::IsStoringOrigin(const url::Origin& origin) const {
  return std::ranges::contains(storing_origins, origin);
}

void CrossOriginStorageEntry::AddStoringOrigin(const url::Origin& origin) {
  if (!IsStoringOrigin(origin)) {
    storing_origins.push_back(origin);
  }
}

}  // namespace content
