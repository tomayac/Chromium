// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_TYPES_H_
#define CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_TYPES_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/time/time.h"
#include "content/common/content_export.h"
#include "url/gurl.h"
#include "third_party/blink/public/mojom/cross_origin_storage/cross_origin_storage.mojom.h"
#include "url/origin.h"

namespace content {

// Implementation-defined constants. None of these are mandated by the spec,
// which deliberately leaves each one open; the values follow the cross-vendor
// engineering notes accompanying the proposal so that independent
// implementations do not diverge needlessly.
// https://github.com/WICG/cross-origin-storage/blob/main/browsers/cross-origin-storage-implementation-notes.md
namespace cos_constants {

// A pending entry whose writer never closed or aborted is reclaimed after this
// long, so an abandoned write cannot wedge a hash indefinitely.
inline constexpr base::TimeDelta kPendingStalenessTimeout = base::Minutes(5);

// Per-origin read rate limit. Every read is a probe, so this bounds how fast an
// origin can enumerate hashes. The burst is sized around sharded AI model
// loading (~2000 shards covers any realistic model).
inline constexpr int kReadProbeBurstCapacity = 2000;
inline constexpr double kReadProbeRefillPerSecond = 20.0;

// Per-origin write rate limit, shared between create requests and the writes
// that follow them. Smaller and slower than the read budget: a write costs the
// caller real bytes, and a legitimate cold load writes each resource once.
inline constexpr int kWriteProbeBurstCapacity = 200;
inline constexpr double kWriteProbeRefillPerSecond = 2.0;

// Bounds the rate limiter's own memory over a long browsing session.
inline constexpr size_t kRateLimiterMaxOrigins = 10000;

// The "maximum origins list length". Bounds both a single call's list and the
// cumulative merged list, so that a list cannot serve as an undeclared
// substitute for "*". Kept in sync with the renderer-side copy.
inline constexpr size_t kMaxOriginsListLength = 100;

// GREASE'ing: the chance that an otherwise-disclosable entry is reported
// absent anyway, and the size at or above which an entry is never GREASE'd
// (because a spurious re-download would be disproportionate to the privacy
// benefit, and its cost would itself be observable).
inline constexpr double kGreaseProbability = 0.01;
inline constexpr int64_t kGreaseSizeCeilingBytes = 500 * 1024;

// Storage budget. Based on total disk capacity rather than free space: free
// space would leak real-time disk state to a probing site and would make COS's
// own growth shrink its own future budget.
inline constexpr double kGlobalBudgetFractionOfDisk = 0.60;
inline constexpr double kPerOriginShareOfGlobalBudget = 0.20;
// An absolute ceiling on the computed budget, as a defense against a platform
// API that misreports disk capacity.
inline constexpr int64_t kGlobalBudgetCeilingBytes = int64_t{100} * 1024 * 1024 * 1024;

// Caps how much disk a single write session can claim through seek()/truncate()
// before the authoritative budget check runs at close() time.
inline constexpr int64_t kStreamingSizeCapBytes = int64_t{4} * 1024 * 1024 * 1024;

}  // namespace cos_constants

// A COS hash: the content identifier an entry is keyed by.
// https://wicg.github.io/cross-origin-storage/#hashes
class CONTENT_EXPORT CrossOriginStorageHash {
 public:
  // Returns a hash with `algorithm` canonicalized, or nullopt if `algorithm` is
  // not recognized by the Web Crypto API or `value` is not a lowercase hex
  // digest of the length that algorithm produces.
  //
  // Every recognized algorithm's digest length is validated, not just
  // SHA-256's: `value` is used to build filesystem paths, so an
  // under-validated digest for a less-common algorithm would be a path
  // traversal vector.
  static std::optional<CrossOriginStorageHash> Create(
      std::string_view algorithm,
      std::string_view value);

  CrossOriginStorageHash(const CrossOriginStorageHash&);
  CrossOriginStorageHash& operator=(const CrossOriginStorageHash&);
  ~CrossOriginStorageHash();

  // Canonical (uppercase) algorithm name, e.g. "SHA-256". Two hashes whose
  // algorithms are an ASCII case-insensitive match canonicalize identically,
  // which is what makes them equal.
  const std::string& algorithm() const { return algorithm_; }
  const std::string& value() const { return value_; }

  bool operator==(const CrossOriginStorageHash& other) const = default;
  // Ordering exists only so this can key a flat_map; it has no meaning.
  auto operator<=>(const CrossOriginStorageHash& other) const = default;

 private:
  CrossOriginStorageHash(std::string algorithm, std::string value);

  std::string algorithm_;
  std::string value_;
};

// The declared sharing scope of an entry.
// https://wicg.github.io/cross-origin-storage/#cos-entries
enum class CrossOriginStorageScope {
  // `origins` is null: same-site origins only.
  kSameSite,
  // `origins` is a (possibly empty) list of origins.
  kList,
  // `origins` is "*".
  kWildcard,
};

// The lifecycle state of an entry. An entry starts pending and becomes written
// exactly once.
enum class CrossOriginStorageEntryState {
  kPending,
  kWritten,
};

// An implementation-private note of where one storing origin claims it got an
// entry's bytes. Deliberately never exposed to script: it is browser state, not
// part of the entry, and a URL is an unverified claim by whoever wrote the
// bytes rather than an attestation about them.
// https://wicg.github.io/cross-origin-storage/#provenance-metadata
struct CONTENT_EXPORT CrossOriginStorageProvenanceRecord {
  CrossOriginStorageProvenanceRecord();
  CrossOriginStorageProvenanceRecord(url::Origin origin,
                                     GURL source_url,
                                     base::Time recorded_at);
  CrossOriginStorageProvenanceRecord(const CrossOriginStorageProvenanceRecord&);
  CrossOriginStorageProvenanceRecord& operator=(
      const CrossOriginStorageProvenanceRecord&);
  ~CrossOriginStorageProvenanceRecord();

  // The origin this claim is attributed to. Discarded along with that origin
  // when it leaves the entry's storing origins.
  url::Origin origin;
  // The URL that origin claims the bytes came from. Empty when unknown, which
  // is the norm for the imperative API: requestFileHandle() never names a URL.
  // The declarative integrations (which fetch from a URL the user agent itself
  // chose) are expected to populate it.
  GURL source_url;
  base::Time recorded_at;
};

// One entry of the COS registry.
// https://wicg.github.io/cross-origin-storage/#cos-entries
struct CONTENT_EXPORT CrossOriginStorageEntry {
  explicit CrossOriginStorageEntry(CrossOriginStorageHash hash);
  CrossOriginStorageEntry(CrossOriginStorageEntry&&);
  CrossOriginStorageEntry& operator=(CrossOriginStorageEntry&&);
  ~CrossOriginStorageEntry();

  // Whether `origin` has itself successfully written this entry, and may
  // therefore always read it back.
  bool IsStoringOrigin(const url::Origin& origin) const;

  // Appends `origin` to the storing origins if not already present.
  void AddStoringOrigin(const url::Origin& origin);

  CrossOriginStorageHash hash;
  CrossOriginStorageEntryState state = CrossOriginStorageEntryState::kPending;

  // Distinguishes this entry from any earlier entry for the same hash that was
  // removed and replaced (for example, a pending entry reclaimed as stale).
  // A handle remembers the generation it was created against, so that a late
  // close() or abort() from an abandoned write can never disturb the bookkeeping
  // of the unrelated entry that replaced it.
  uint64_t generation = 0;

  // Size of the stored bytes. Only meaningful once written.
  int64_t size = 0;

  // Outstanding writers: handles handed out by a create request whose closing
  // write has not yet settled. Used solely to decide whether a failed write may
  // clean the entry up, so that a failing writer never disturbs a concurrent
  // sibling write for the same hash.
  int pending_writer_count = 0;

  CrossOriginStorageScope scope = CrossOriginStorageScope::kSameSite;
  // Only meaningful when `scope` is kList. Duplicate-free.
  std::vector<url::Origin> origins;

  // Origins that have each successfully written these bytes at least once.
  // Grows over time; only shrinks when an origin's site data is cleared.
  std::vector<url::Origin> storing_origins;

  // The origin whose write first transitioned this entry to written. The
  // entry's byte cost is charged against that origin's budget share.
  //
  // TODO(tomayac): this single-origin attribution is a known
  // simplification. A second origin that independently writes the identical
  // bytes correctly adds no second charge against the global total, but also
  // gets nothing charged against its own share; and a site-scoped clear that
  // removes the attributed origin leaves the charge stale rather than
  // reattributing it.
  std::optional<url::Origin> attributed_origin;

  // When this entry was created. Used to reclaim a pending entry whose writer
  // never reported back at all.
  base::Time created_at;
  // When this entry was last successfully read. Eviction is oldest-read-first,
  // so that an entry a writer keeps re-verifying but nobody reads is evicted
  // before one actively serving readers.
  base::Time last_read_at;

  std::vector<CrossOriginStorageProvenanceRecord> provenance;
};

}  // namespace content

#endif  // CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_TYPES_H_
