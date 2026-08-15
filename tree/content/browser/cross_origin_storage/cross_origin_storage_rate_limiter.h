// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_RATE_LIMITER_H_
#define CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_RATE_LIMITER_H_

#include <stddef.h>

#include <map>

#include "base/time/time.h"
#include "content/common/content_export.h"
#include "url/origin.h"

namespace content {

// A per-origin token bucket, used to bound how fast one origin can probe the
// COS registry.
//
// Every read is a probe: its outcome is directly observable by script, so
// without a limit an origin could enumerate hashes to infer what a user has
// visited. Denials are deliberately not distinguishable from a genuine miss by
// the caller -- surfacing "you are being rate limited" would make the limiter
// its own oracle. See
// https://wicg.github.io/cross-origin-storage/#cross-site-probing
//
// The map of buckets is itself capped and evicts least-recently-used entries,
// so a long session visiting many sites cannot grow it without bound.
class CONTENT_EXPORT CrossOriginStorageRateLimiter {
 public:
  CrossOriginStorageRateLimiter(int capacity,
                                double refill_per_second,
                                size_t max_origins);
  CrossOriginStorageRateLimiter(const CrossOriginStorageRateLimiter&) = delete;
  CrossOriginStorageRateLimiter& operator=(
      const CrossOriginStorageRateLimiter&) = delete;
  ~CrossOriginStorageRateLimiter();

  // Consumes one token for `origin`. Returns false if the origin is over
  // budget, in which case the caller must respond exactly as it would to a
  // genuine miss.
  bool TryConsume(const url::Origin& origin);

  // Drops all state for `origin`, e.g. when its site data is cleared.
  void RemoveOrigin(const url::Origin& origin);

  void Clear();

  void SetTickClockForTesting(base::TimeTicks (*now_fn)());

 private:
  struct Bucket {
    double tokens = 0;
    // Doubles as the recency signal for LRU eviction: every consumption
    // attempt, allowed or denied, updates it.
    base::TimeTicks last_update;
  };

  base::TimeTicks Now() const;

  // Removes the least recently touched bucket. Worst case for the evicted
  // origin is a reset burst, equivalent to what it would see after a browser
  // restart -- a memory bound, not a correctness concern.
  void EvictLeastRecentlyUsed();

  const int capacity_;
  const double refill_per_second_;
  const size_t max_origins_;

  std::map<url::Origin, Bucket> buckets_;

  base::TimeTicks (*now_fn_for_testing_)() = nullptr;
};

}  // namespace content

#endif  // CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_RATE_LIMITER_H_
