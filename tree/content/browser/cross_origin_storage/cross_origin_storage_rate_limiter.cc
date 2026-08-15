// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_rate_limiter.h"

#include <algorithm>

namespace content {

CrossOriginStorageRateLimiter::CrossOriginStorageRateLimiter(
    int capacity,
    double refill_per_second,
    size_t max_origins)
    : capacity_(capacity),
      refill_per_second_(refill_per_second),
      max_origins_(max_origins) {}

CrossOriginStorageRateLimiter::~CrossOriginStorageRateLimiter() = default;

base::TimeTicks CrossOriginStorageRateLimiter::Now() const {
  return now_fn_for_testing_ ? now_fn_for_testing_() : base::TimeTicks::Now();
}

bool CrossOriginStorageRateLimiter::TryConsume(const url::Origin& origin) {
  const base::TimeTicks now = Now();

  auto it = buckets_.find(origin);
  if (it == buckets_.end()) {
    if (buckets_.size() >= max_origins_) {
      EvictLeastRecentlyUsed();
    }
    it = buckets_.emplace(origin, Bucket{static_cast<double>(capacity_), now})
             .first;
  } else {
    const double elapsed_seconds = (now - it->second.last_update).InSecondsF();
    it->second.tokens = std::min(static_cast<double>(capacity_),
                                 it->second.tokens +
                                     elapsed_seconds * refill_per_second_);
  }

  // Updated whether or not the request is allowed, both to refill correctly and
  // so that a denied origin still counts as recently active for LRU purposes.
  it->second.last_update = now;

  if (it->second.tokens < 1.0) {
    return false;
  }
  it->second.tokens -= 1.0;
  return true;
}

void CrossOriginStorageRateLimiter::RemoveOrigin(const url::Origin& origin) {
  buckets_.erase(origin);
}

void CrossOriginStorageRateLimiter::Clear() {
  buckets_.clear();
}

void CrossOriginStorageRateLimiter::SetTickClockForTesting(
    base::TimeTicks (*now_fn)()) {
  now_fn_for_testing_ = now_fn;
}

void CrossOriginStorageRateLimiter::EvictLeastRecentlyUsed() {
  if (buckets_.empty()) {
    return;
  }
  auto oldest = buckets_.begin();
  for (auto it = std::next(buckets_.begin()); it != buckets_.end(); ++it) {
    if (it->second.last_update < oldest->second.last_update) {
      oldest = it;
    }
  }
  buckets_.erase(oldest);
}

}  // namespace content
