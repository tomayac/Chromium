// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_REGISTRY_H_
#define CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_REGISTRY_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/sequence_checker.h"
#include "base/supports_user_data.h"
#include "base/task/sequenced_task_runner.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_public_hash_list.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_rate_limiter.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_types.h"
#include "content/common/content_export.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/unique_receiver_set.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_handle.mojom.h"
#include "url/origin.h"

namespace content {

class BrowserContext;
class CrossOriginStorageFileHandleImpl;

// The browser-wide Cross-Origin Storage registry: a map from COS hashes to
// entries, shared by every origin in a BrowserContext.
// https://wicg.github.io/cross-origin-storage/#cos-entries
//
// This owns every spec algorithm and every policy decision -- the entry state
// machine, disclosure scoping, availability gating, hash verification, quota,
// eviction, and rate limiting. The renderer-side class is a thin IPC client
// that owns none of it, and nothing this class is sent over IPC is trusted:
// a compromised renderer can speak that interface directly, so hashes and
// origins are re-validated here before they reach any filesystem path.
//
// Lives on the UI thread; all blocking file I/O is posted to `file_runner_`.
// Because every decision below is made synchronously on one sequence, the
// operations are naturally serialized in the order they arrive, which is what
// the spec's "Cross-Origin Storage queue" requires.
class CONTENT_EXPORT CrossOriginStorageRegistry
    : public base::SupportsUserData::Data {
 public:
  using RequestFileHandleCallback = base::OnceCallback<void(
      blink::mojom::FileSystemAccessErrorPtr,
      mojo::PendingRemote<blink::mojom::FileSystemAccessFileHandle>)>;
  using WriteCompleteCallback =
      base::OnceCallback<void(blink::mojom::FileSystemAccessErrorPtr)>;

  // Returns the registry for `browser_context`, creating it on first use. An
  // off-the-record context gets its own registry backed by a temporary
  // directory that is discarded with the profile, so nothing an incognito
  // session stores outlives it or is visible to the on-the-record profile.
  static CrossOriginStorageRegistry* GetOrCreateForBrowserContext(
      BrowserContext* browser_context);

  // `browser_context` may be null in unit tests that exercise registry logic
  // without a blob context; AsBlob() then fails rather than crashing.
  CrossOriginStorageRegistry(BrowserContext* browser_context,
                             const base::FilePath& root_directory,
                             bool is_off_the_record);
  CrossOriginStorageRegistry(const CrossOriginStorageRegistry&) = delete;
  CrossOriginStorageRegistry& operator=(const CrossOriginStorageRegistry&) =
      delete;
  ~CrossOriginStorageRegistry() override;

  // Implements requestFileHandle(). `origin` is the calling context's origin as
  // the browser knows it, never a value the renderer supplied.
  void RequestFileHandle(const url::Origin& origin,
                         const std::string& algorithm,
                         const std::string& value,
                         bool create,
                         CrossOriginStorageScope scope,
                         std::vector<url::Origin> origins,
                         RequestFileHandleCallback callback);

  // "Verify and store": called when a writable stream addressing a COS entry
  // closes. `computed_value` is the lowercase hex digest of everything actually
  // written, computed over the final file rather than accumulated per write,
  // since a later seek()/truncate() can invalidate bytes already seen.
  // https://wicg.github.io/cross-origin-storage/#verify-and-store
  void FinishWrite(const CrossOriginStorageHash& hash,
                   uint64_t generation,
                   const url::Origin& origin,
                   CrossOriginStorageScope requested_scope,
                   std::vector<url::Origin> requested_origins,
                   const GURL& source_url,
                   base::FilePath swap_path,
                   int64_t size,
                   const std::string& computed_value,
                   WriteCompleteCallback callback);

  // Called when a writer will never succeed -- an explicit abort(), a dropped
  // pipe, or a terminal I/O failure. Funnels into the same cleanup a failed
  // close() runs, which is what keeps an abandoned write from wedging a hash
  // for every other origin.
  void AbandonWrite(const CrossOriginStorageHash& hash, uint64_t generation);

  // Returns the entry for `hash` if it exists and is written, else null.
  const CrossOriginStorageEntry* FindWrittenEntry(
      const CrossOriginStorageHash& hash) const;

  // Where an entry's bytes live once published.
  base::FilePath GetBytesPath(const CrossOriginStorageHash& hash) const;

  // A fresh path for an in-progress write's swap file.
  base::FilePath CreateSwapPath();

  // The stable, nominal number of bytes a single origin may hold. Derived from
  // total disk capacity rather than free space, so that a rejection cannot leak
  // real-time disk state to a probing site and so COS's own growth does not
  // shrink its own future budget.
  int64_t per_origin_quota_bytes() const { return per_origin_quota_bytes_; }

  scoped_refptr<base::SequencedTaskRunner> file_runner() const {
    return file_runner_;
  }

  BrowserContext* browser_context() const { return browser_context_; }

  // Removes every entry, in memory and on disk. Unambiguous: unlike a
  // site-scoped clear there is no shared ownership to reason about.
  void ClearAllData(base::OnceClosure done);

  // Removes `origin` from every entry it is associated with -- its storing
  // origins and any explicit origins-list grant naming it -- and deletes an
  // entry outright only if that leaves it with no storing origin at all.
  //
  // This is a revoke-and-GC policy rather than delete-if-involved: an entry a
  // different, uncleared site also legitimately stored keeps working. Clearing
  // site A's data silently destroying site B's data, for an action B was never
  // part of, is the worse failure mode. Neither the spec nor the explainer
  // settles this; see the implementation notes' clear-data section.
  void ClearDataForOrigin(const url::Origin& origin, base::OnceClosure done);

  // As above, for every origin `matcher` accepts.
  void ClearDataWithFilter(
      base::RepeatingCallback<bool(const url::Origin&)> matcher,
      base::OnceClosure done);

  // Test seams.
  CrossOriginStoragePublicHashList& public_hash_list_for_testing() {
    return public_hash_list_;
  }
  void SetGreaseDisabledForTesting(bool disabled) {
    grease_disabled_for_testing_ = disabled;
  }
  void SetPerOriginQuotaForTesting(int64_t bytes) {
    per_origin_quota_bytes_ = bytes;
  }
  const std::map<CrossOriginStorageHash, CrossOriginStorageEntry>&
  entries_for_testing() const {
    return entries_;
  }
  CrossOriginStorageEntry* FindEntryForTesting(
      const CrossOriginStorageHash& hash);
  void WaitForInitializationForTesting();

  // Inserts an entry directly, bypassing the write path, so that the
  // disclosure and eviction decisions can be exercised without file I/O.
  // Returns the entry's generation.
  uint64_t AddWrittenEntryForTesting(const CrossOriginStorageHash& hash,
                                     int64_t size,
                                     CrossOriginStorageScope scope,
                                     std::vector<url::Origin> origins,
                                     std::vector<url::Origin> storing_origins);
  uint64_t AddPendingEntryForTesting(const CrossOriginStorageHash& hash,
                                     int pending_writer_count);

  // Runs "apply availability gating" for `origin`, the decision that governs
  // every read.
  bool IsDisclosableForTesting(const CrossOriginStorageHash& hash,
                               const url::Origin& origin);

  void UpgradeVisibilityForTesting(const CrossOriginStorageHash& hash,
                                   CrossOriginStorageScope requested_scope,
                                   const std::vector<url::Origin>& requested);

  base::WeakPtr<CrossOriginStorageRegistry> GetWeakPtr();

 private:
  struct LoadedState;

  void OnInitialized(std::unique_ptr<LoadedState> state);

  void RequestFileHandleInternal(const url::Origin& origin,
                                 CrossOriginStorageHash hash,
                                 bool create,
                                 CrossOriginStorageScope scope,
                                 std::vector<url::Origin> origins,
                                 RequestFileHandleCallback callback);

  // https://wicg.github.io/cross-origin-storage/#reading-files
  void CompleteReadRequest(const url::Origin& origin,
                           const CrossOriginStorageHash& hash,
                           RequestFileHandleCallback callback);

  // https://wicg.github.io/cross-origin-storage/#creating-and-writing-files
  void CompleteCreateRequest(const url::Origin& origin,
                             const CrossOriginStorageHash& hash,
                             CrossOriginStorageScope scope,
                             std::vector<url::Origin> origins,
                             RequestFileHandleCallback callback);

  // "Determine COS disclosure": whether `origin` is allowed to read `entry` at
  // all. https://wicg.github.io/cross-origin-storage/#determine-cos-disclosure
  bool DetermineDisclosure(const CrossOriginStorageEntry& entry,
                           const url::Origin& origin);

  // "Apply availability gating": disclosure, plus the user agent's own
  // willingness to confirm the entry exists.
  // https://wicg.github.io/cross-origin-storage/#apply-availability-gating
  bool ApplyAvailabilityGating(const CrossOriginStorageEntry& entry,
                               const url::Origin& origin);

  // Whether to suppress an otherwise-permitted disclosure this once. Never
  // applied to a large entry: a false negative there forces a costly, fully
  // observable re-download, which would defeat the point.
  // https://wicg.github.io/cross-origin-storage/#greasing
  bool ShouldGrease(const CrossOriginStorageEntry& entry) const;

  // "Upgrade resource visibility": widen, never narrow.
  // https://wicg.github.io/cross-origin-storage/#upgrade-resource-visibility
  void UpgradeResourceVisibility(CrossOriginStorageEntry& entry,
                                 CrossOriginStorageScope requested_scope,
                                 const std::vector<url::Origin>& requested);

  // A pending entry nobody ever reported back on reads as absent and is
  // replaced by the next create request, so neither readers nor writers are
  // blocked forever by a page that navigated away mid-write.
  bool IsStale(const CrossOriginStorageEntry& entry) const;

  // Drops `entry` if it never reached written and no writer is still
  // outstanding. Both qualifiers matter: the count protects a concurrent
  // sibling write from a failing writer's cleanup, and the never-written
  // qualifier stops any origin from deleting bytes another origin already
  // stored just by writing garbage under the same hash.
  void MaybeRemovePendingEntry(const CrossOriginStorageHash& hash);

  void RemoveEntry(const CrossOriginStorageHash& hash);

  void OnBytesPublished(CrossOriginStorageHash hash,
                        uint64_t generation,
                        url::Origin origin,
                        CrossOriginStorageScope requested_scope,
                        std::vector<url::Origin> requested_origins,
                        GURL source_url,
                        int64_t size,
                        WriteCompleteCallback callback,
                        bool success);

  // Two passes, in order: first evict the writing origin's own sole-owned
  // entries if it is over its share, then evict anything if the registry is
  // still over the global cap. An origin can never force eviction of another
  // origin's data merely by writing more.
  void EnforceStorageBudget(const url::Origin& writing_origin);
  int64_t GetOriginUsage(const url::Origin& origin) const;

  void PersistEntry(const CrossOriginStorageEntry& entry);
  void DeletePersistedEntry(const CrossOriginStorageHash& hash);

  base::FilePath GetMetadataPath(const CrossOriginStorageHash& hash) const;

  SEQUENCE_CHECKER(sequence_checker_);

  const raw_ptr<BrowserContext> browser_context_;
  const base::FilePath root_directory_;
  const bool is_off_the_record_;
  scoped_refptr<base::SequencedTaskRunner> file_runner_;

  // Set once the on-disk state has been loaded. Requests that arrive first are
  // queued rather than answered against an empty registry, which would
  // otherwise report a stored entry as missing right after startup.
  bool initialized_ = false;
  std::vector<base::OnceClosure> pending_initialization_callbacks_;

  std::map<CrossOriginStorageHash, CrossOriginStorageEntry> entries_;

  // Maintained incrementally at every mutation site rather than recomputed by
  // scanning every entry, which would be an O(n) cost on every single write.
  int64_t total_bytes_used_ = 0;
  std::map<url::Origin, int64_t> per_origin_bytes_used_;

  uint64_t next_generation_ = 1;

  int64_t global_quota_bytes_ = 0;
  int64_t per_origin_quota_bytes_ = 0;

  CrossOriginStoragePublicHashList public_hash_list_;
  CrossOriginStorageRateLimiter read_limiter_;
  CrossOriginStorageRateLimiter write_limiter_;

  mojo::UniqueReceiverSet<blink::mojom::FileSystemAccessFileHandle> handles_;

  bool grease_disabled_for_testing_ = false;

  base::WeakPtrFactory<CrossOriginStorageRegistry> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_REGISTRY_H_
