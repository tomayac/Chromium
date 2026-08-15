// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_registry.h"

#include <algorithm>
#include <utility>

#include "base/files/file_enumerator.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/pickle.h"
#include "base/rand_util.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/system/sys_info.h"
#include "base/task/thread_pool.h"
#include "base/uuid.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_file_handle_impl.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "net/base/schemeful_site.h"

namespace content {

namespace {

constexpr char kUserDataKey[] = "cross_origin_storage_registry";

constexpr base::FilePath::CharType kDirectoryName[] =
    FILE_PATH_LITERAL("CrossOriginStorage");
constexpr base::FilePath::CharType kSwapDirectoryName[] =
    FILE_PATH_LITERAL("swap");
constexpr base::FilePath::CharType kBytesExtension[] =
    FILE_PATH_LITERAL(".bytes");
constexpr base::FilePath::CharType kMetadataExtension[] =
    FILE_PATH_LITERAL(".meta");
constexpr base::FilePath::CharType kTempExtension[] = FILE_PATH_LITERAL(".tmp");

// Bumped if the on-disk metadata layout changes. Entries written by a newer
// version are ignored rather than misparsed.
constexpr uint32_t kMetadataVersion = 1;

blink::mojom::FileSystemAccessErrorPtr Ok() {
  return blink::mojom::FileSystemAccessError::New(
      blink::mojom::FileSystemAccessStatus::kOk, base::File::FILE_OK, "");
}

blink::mojom::FileSystemAccessErrorPtr Error(
    blink::mojom::FileSystemAccessStatus status,
    std::string message) {
  return blink::mojom::FileSystemAccessError::New(status, base::File::FILE_OK,
                                                  std::move(message));
}

// Every non-success read outcome is this exact error, so that a caller cannot
// tell a genuine miss from an out-of-scope resource, an unlisted "*"-scoped
// one, a GREASE'd one, or a rate-limited probe.
// https://wicg.github.io/cross-origin-storage/#availability-gating
blink::mojom::FileSystemAccessErrorPtr NotFound() {
  return blink::mojom::FileSystemAccessError::New(
      blink::mojom::FileSystemAccessStatus::kFileError,
      base::File::FILE_ERROR_NOT_FOUND,
      "The requested file was not found in Cross-Origin Storage.");
}

base::FilePath::StringType HashDirectoryComponent(
    const CrossOriginStorageHash& hash) {
  // The algorithm is one of a fixed set of canonical names and the value has
  // already been validated as pure lowercase hex, so neither can escape the
  // storage directory.
#if BUILDFLAG(IS_WIN)
  return base::UTF8ToWide(hash.algorithm());
#else
  return hash.algorithm();
#endif
}

base::FilePath::StringType HashFileComponent(
    const CrossOriginStorageHash& hash) {
#if BUILDFLAG(IS_WIN)
  return base::UTF8ToWide(hash.value());
#else
  return hash.value();
#endif
}

// Writes `data` to `path` by way of a sibling temp file that is then renamed
// into place, so a reader never observes a half-written file. The temp name is
// derived from the final name rather than randomized, so that the startup scan
// can recognize and discard an orphan left by a crash.
bool WriteFileAtomically(const base::FilePath& path,
                         base::span<const uint8_t> data) {
  const base::FilePath temp_path = path.AddExtension(kTempExtension);
  if (!base::WriteFile(temp_path, data)) {
    base::DeleteFile(temp_path);
    return false;
  }
  if (!base::ReplaceFile(temp_path, path, nullptr)) {
    base::DeleteFile(temp_path);
    return false;
  }
  return true;
}

void SerializeEntry(const CrossOriginStorageEntry& entry, base::Pickle* pickle) {
  pickle->WriteUInt32(kMetadataVersion);
  pickle->WriteString(entry.hash.algorithm());
  pickle->WriteString(entry.hash.value());
  pickle->WriteInt64(entry.size);
  pickle->WriteInt(static_cast<int>(entry.scope));

  pickle->WriteUInt32(static_cast<uint32_t>(entry.origins.size()));
  for (const auto& origin : entry.origins) {
    pickle->WriteString(origin.Serialize());
  }

  pickle->WriteUInt32(static_cast<uint32_t>(entry.storing_origins.size()));
  for (const auto& origin : entry.storing_origins) {
    pickle->WriteString(origin.Serialize());
  }

  pickle->WriteBool(entry.attributed_origin.has_value());
  if (entry.attributed_origin) {
    pickle->WriteString(entry.attributed_origin->Serialize());
  }

  pickle->WriteInt64(entry.created_at.ToDeltaSinceWindowsEpoch().InMicroseconds());
  pickle->WriteInt64(
      entry.last_read_at.ToDeltaSinceWindowsEpoch().InMicroseconds());

  pickle->WriteUInt32(static_cast<uint32_t>(entry.provenance.size()));
  for (const auto& record : entry.provenance) {
    pickle->WriteString(record.origin.Serialize());
    pickle->WriteString(record.source_url.spec());
    pickle->WriteInt64(
        record.recorded_at.ToDeltaSinceWindowsEpoch().InMicroseconds());
  }
}

std::optional<CrossOriginStorageEntry> DeserializeEntry(
    base::span<const uint8_t> data) {
  base::Pickle pickle = base::Pickle::WithData(data);
  base::PickleIterator it(pickle);

  uint32_t version = 0;
  if (!it.ReadUInt32(&version) || version != kMetadataVersion) {
    return std::nullopt;
  }

  std::string algorithm;
  std::string value;
  if (!it.ReadString(&algorithm) || !it.ReadString(&value)) {
    return std::nullopt;
  }
  // Re-validated on load rather than trusted: this value becomes a filesystem
  // path, and the file it came from is not more trustworthy than any other
  // input just because it lives in the profile directory.
  std::optional<CrossOriginStorageHash> hash =
      CrossOriginStorageHash::Create(algorithm, value);
  if (!hash) {
    return std::nullopt;
  }

  CrossOriginStorageEntry entry(*hash);
  entry.state = CrossOriginStorageEntryState::kWritten;

  int scope = 0;
  if (!it.ReadInt64(&entry.size) || !it.ReadInt(&scope) || entry.size < 0) {
    return std::nullopt;
  }
  if (scope < static_cast<int>(CrossOriginStorageScope::kSameSite) ||
      scope > static_cast<int>(CrossOriginStorageScope::kWildcard)) {
    return std::nullopt;
  }
  entry.scope = static_cast<CrossOriginStorageScope>(scope);

  auto read_origins = [&it](std::vector<url::Origin>* out) {
    uint32_t count = 0;
    if (!it.ReadUInt32(&count) || count > cos_constants::kMaxOriginsListLength) {
      return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
      std::string serialized;
      if (!it.ReadString(&serialized)) {
        return false;
      }
      url::Origin origin = url::Origin::Create(GURL(serialized));
      if (origin.opaque()) {
        return false;
      }
      out->push_back(std::move(origin));
    }
    return true;
  };

  if (!read_origins(&entry.origins)) {
    return std::nullopt;
  }
  // Storing origins can legitimately exceed the origins-list cap, since it
  // grows with every independent writer rather than being declared.
  uint32_t storing_count = 0;
  if (!it.ReadUInt32(&storing_count)) {
    return std::nullopt;
  }
  for (uint32_t i = 0; i < storing_count; ++i) {
    std::string serialized;
    if (!it.ReadString(&serialized)) {
      return std::nullopt;
    }
    url::Origin origin = url::Origin::Create(GURL(serialized));
    if (origin.opaque()) {
      return std::nullopt;
    }
    entry.storing_origins.push_back(std::move(origin));
  }

  bool has_attributed = false;
  if (!it.ReadBool(&has_attributed)) {
    return std::nullopt;
  }
  if (has_attributed) {
    std::string serialized;
    if (!it.ReadString(&serialized)) {
      return std::nullopt;
    }
    entry.attributed_origin = url::Origin::Create(GURL(serialized));
  }

  int64_t created_us = 0;
  int64_t last_read_us = 0;
  if (!it.ReadInt64(&created_us) || !it.ReadInt64(&last_read_us)) {
    return std::nullopt;
  }
  entry.created_at =
      base::Time::FromDeltaSinceWindowsEpoch(base::Microseconds(created_us));
  entry.last_read_at =
      base::Time::FromDeltaSinceWindowsEpoch(base::Microseconds(last_read_us));

  uint32_t provenance_count = 0;
  if (!it.ReadUInt32(&provenance_count)) {
    return std::nullopt;
  }
  for (uint32_t i = 0; i < provenance_count; ++i) {
    std::string origin_str;
    std::string url_str;
    int64_t recorded_us = 0;
    if (!it.ReadString(&origin_str) || !it.ReadString(&url_str) ||
        !it.ReadInt64(&recorded_us)) {
      return std::nullopt;
    }
    entry.provenance.emplace_back(
        url::Origin::Create(GURL(origin_str)), GURL(url_str),
        base::Time::FromDeltaSinceWindowsEpoch(
            base::Microseconds(recorded_us)));
  }

  return entry;
}

}  // namespace

struct CrossOriginStorageRegistry::LoadedState {
  std::vector<CrossOriginStorageEntry> entries;
  int64_t total_disk_capacity = 0;
  // Read here, on a sequence that permits blocking, rather than lazily on
  // first lookup: the availability-gating decision it feeds runs on the UI
  // thread, which must never block on disk.
  std::vector<uint8_t> public_hash_list;
};

// static
CrossOriginStorageRegistry*
CrossOriginStorageRegistry::GetOrCreateForBrowserContext(
    BrowserContext* browser_context) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  auto* existing = static_cast<CrossOriginStorageRegistry*>(
      browser_context->GetUserData(kUserDataKey));
  if (existing) {
    return existing;
  }

  // An off-the-record profile has no persistent path of its own, so its
  // registry gets a temporary directory that is discarded with the session.
  // Nothing an incognito session stores is visible to the regular profile, and
  // nothing survives it.
  base::FilePath root = browser_context->GetPath();
  if (root.empty()) {
    base::FilePath temp_dir;
    if (!base::GetTempDir(&temp_dir)) {
      return nullptr;
    }
    root = temp_dir.AppendASCII(
        "cos-" + base::Uuid::GenerateRandomV4().AsLowercaseString());
  }

  auto registry = std::make_unique<CrossOriginStorageRegistry>(
      browser_context, root.Append(kDirectoryName),
      browser_context->IsOffTheRecord());
  auto* raw = registry.get();
  browser_context->SetUserData(kUserDataKey, std::move(registry));
  return raw;
}

CrossOriginStorageRegistry::CrossOriginStorageRegistry(
    BrowserContext* browser_context,
    const base::FilePath& root_directory,
    bool is_off_the_record)
    : browser_context_(browser_context),
      root_directory_(root_directory),
      is_off_the_record_(is_off_the_record),
      file_runner_(base::ThreadPool::CreateSequencedTaskRunner(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
           base::TaskShutdownBehavior::BLOCK_SHUTDOWN})),
      read_limiter_(cos_constants::kReadProbeBurstCapacity,
                    cos_constants::kReadProbeRefillPerSecond,
                    cos_constants::kRateLimiterMaxOrigins),
      write_limiter_(cos_constants::kWriteProbeBurstCapacity,
                     cos_constants::kWriteProbeRefillPerSecond,
                     cos_constants::kRateLimiterMaxOrigins) {
  base::FilePath root = root_directory_;
  bool skip_load = is_off_the_record_;
  file_runner_->PostTaskAndReplyWithResult(
      FROM_HERE, base::BindOnce(
                     [](base::FilePath root, bool skip_load) {
                       auto state = std::make_unique<LoadedState>();
                       base::CreateDirectory(root);
                       base::CreateDirectory(root.Append(kSwapDirectoryName));
                       state->total_disk_capacity =
                           base::SysInfo::AmountOfTotalDiskSpace(root).value_or(
                               0);
                       state->public_hash_list =
                           CrossOriginStoragePublicHashList::LoadFromDisk();

                       if (skip_load) {
                         return state;
                       }

                       base::FileEnumerator dirs(
                           root, /*recursive=*/false,
                           base::FileEnumerator::DIRECTORIES);
                       for (base::FilePath dir = dirs.Next(); !dir.empty();
                            dir = dirs.Next()) {
                         if (dir.BaseName().value() == kSwapDirectoryName) {
                           continue;
                         }
                         base::FileEnumerator files(
                             dir, /*recursive=*/false,
                             base::FileEnumerator::FILES);
                         for (base::FilePath file = files.Next(); !file.empty();
                              file = files.Next()) {
                           // An orphan left by a crash between writing a temp
                           // file and renaming it. The rename never happened,
                           // so discarding it is always safe.
                           if (file.MatchesExtension(kTempExtension)) {
                             base::DeleteFile(file);
                             continue;
                           }
                           if (!file.MatchesExtension(kMetadataExtension)) {
                             continue;
                           }
                           std::optional<std::vector<uint8_t>> data =
                               base::ReadFileToBytes(file);
                           if (!data) {
                             continue;
                           }
                           std::optional<CrossOriginStorageEntry> entry =
                               DeserializeEntry(*data);
                           if (!entry) {
                             continue;
                           }
                           // A metadata file whose bytes are missing or the
                           // wrong size degrades to "absent" rather than being
                           // served under a hash it no longer matches.
                           base::FilePath bytes_path =
                               file.RemoveExtension().AddExtension(
                                   kBytesExtension);
                           std::optional<int64_t> size =
                               base::GetFileSize(bytes_path);
                           if (!size || *size != entry->size) {
                             base::DeleteFile(file);
                             base::DeleteFile(bytes_path);
                             continue;
                           }
                           state->entries.push_back(std::move(*entry));
                         }
                       }
                       return state;
                     },
                     root, skip_load),
      base::BindOnce(&CrossOriginStorageRegistry::OnInitialized,
                     weak_factory_.GetWeakPtr()));
}

CrossOriginStorageRegistry::~CrossOriginStorageRegistry() {
  if (is_off_the_record_ && !root_directory_.empty()) {
    file_runner_->PostTask(
        FROM_HERE,
        base::GetDeletePathRecursivelyCallback(root_directory_));
  }
}

void CrossOriginStorageRegistry::OnInitialized(
    std::unique_ptr<LoadedState> state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Recomputed from scratch exactly once, here. Every later mutation maintains
  // the totals incrementally; scanning every entry on each write would be an
  // O(n) cost at a scale where n is hundreds of thousands.
  for (auto& entry : state->entries) {
    total_bytes_used_ += entry.size;
    if (entry.attributed_origin) {
      per_origin_bytes_used_[*entry.attributed_origin] += entry.size;
    }
    entry.generation = next_generation_++;
    CrossOriginStorageHash hash = entry.hash;
    entries_.insert({std::move(hash), std::move(entry)});
  }

  public_hash_list_.SetPackedDigests(std::move(state->public_hash_list));

  const int64_t capacity = state->total_disk_capacity;
  if (capacity > 0) {
    global_quota_bytes_ = std::min(
        static_cast<int64_t>(capacity *
                             cos_constants::kGlobalBudgetFractionOfDisk),
        cos_constants::kGlobalBudgetCeilingBytes);
  } else {
    // A platform that cannot report capacity gets the ceiling rather than an
    // unbounded budget.
    global_quota_bytes_ = cos_constants::kGlobalBudgetCeilingBytes;
  }
  per_origin_quota_bytes_ = static_cast<int64_t>(
      global_quota_bytes_ * cos_constants::kPerOriginShareOfGlobalBudget);

  initialized_ = true;
  std::vector<base::OnceClosure> queued;
  queued.swap(pending_initialization_callbacks_);
  for (auto& callback : queued) {
    std::move(callback).Run();
  }
}

void CrossOriginStorageRegistry::RequestFileHandle(
    const url::Origin& origin,
    const std::string& algorithm,
    const std::string& value,
    bool create,
    CrossOriginStorageScope scope,
    std::vector<url::Origin> origins,
    RequestFileHandleCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Re-validated here regardless of what the renderer already checked: a
  // compromised renderer can speak this interface directly, and `value` becomes
  // part of a filesystem path.
  std::optional<CrossOriginStorageHash> hash =
      CrossOriginStorageHash::Create(algorithm, value);
  if (!hash) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidArgument,
              "The hash is not a recognized algorithm and digest."),
        mojo::NullRemote());
    return;
  }
  if (origins.size() > cos_constants::kMaxOriginsListLength) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidArgument,
              "Too many origins."),
        mojo::NullRemote());
    return;
  }
  for (const auto& listed : origins) {
    if (listed.opaque()) {
      std::move(callback).Run(
          Error(blink::mojom::FileSystemAccessStatus::kInvalidArgument,
                "An origin is opaque."),
          mojo::NullRemote());
      return;
    }
  }

  if (!initialized_) {
    // Answering before the persisted registry is loaded would report a stored
    // entry as missing, so queue instead.
    pending_initialization_callbacks_.push_back(base::BindOnce(
        &CrossOriginStorageRegistry::RequestFileHandleInternal,
        weak_factory_.GetWeakPtr(), origin, *hash, create, scope,
        std::move(origins), std::move(callback)));
    return;
  }
  RequestFileHandleInternal(origin, *hash, create, scope, std::move(origins),
                            std::move(callback));
}

void CrossOriginStorageRegistry::RequestFileHandleInternal(
    const url::Origin& origin,
    CrossOriginStorageHash hash,
    bool create,
    CrossOriginStorageScope scope,
    std::vector<url::Origin> origins,
    RequestFileHandleCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (create) {
    CompleteCreateRequest(origin, hash, scope, std::move(origins),
                          std::move(callback));
  } else {
    CompleteReadRequest(origin, hash, std::move(callback));
  }
}

void CrossOriginStorageRegistry::CompleteReadRequest(
    const url::Origin& origin,
    const CrossOriginStorageHash& hash,
    RequestFileHandleCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // A denial must be indistinguishable from a genuine miss, or the limiter
  // becomes its own oracle: a caller could binary search for the limit, or use
  // "am I limited yet" as a side channel.
  if (!read_limiter_.TryConsume(origin)) {
    std::move(callback).Run(NotFound(), mojo::NullRemote());
    return;
  }

  auto it = entries_.find(hash);
  if (it == entries_.end()) {
    std::move(callback).Run(NotFound(), mojo::NullRemote());
    return;
  }

  CrossOriginStorageEntry& entry = it->second;
  if (entry.state == CrossOriginStorageEntryState::kPending) {
    if (IsStale(entry)) {
      // Nobody is coming back for this one. Reading it as absent keeps a
      // reader from waiting behind a write that will never finish.
      std::move(callback).Run(NotFound(), mojo::NullRemote());
      return;
    }
    // A write genuinely in flight deliberately does not look like a miss, so a
    // reader does not start a redundant download of a file that may already be
    // most of the way written.
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kPermissionDenied,
              "A write for this hash is already in progress."),
        mojo::NullRemote());
    return;
  }

  if (!ApplyAvailabilityGating(entry, origin)) {
    std::move(callback).Run(NotFound(), mojo::NullRemote());
    return;
  }

  entry.last_read_at = base::Time::Now();
  // A read by a listed origin refreshes its recency, so that the merge-time cap
  // drops genuinely dormant origins first. A writer re-declaring an origin
  // deliberately does not refresh it, or a dormant origin could be kept alive
  // forever without ever being used.
  if (entry.scope == CrossOriginStorageScope::kList) {
    auto listed = std::ranges::find(entry.origins, origin);
    if (listed != entry.origins.end()) {
      std::rotate(listed, listed + 1, entry.origins.end());
    }
  }
  PersistEntry(entry);

  auto handle = CrossOriginStorageFileHandleImpl::CreateForRead(
      weak_factory_.GetWeakPtr(), origin, hash);
  mojo::PendingRemote<blink::mojom::FileSystemAccessFileHandle> remote;
  handles_.Add(std::move(handle), remote.InitWithNewPipeAndPassReceiver());
  std::move(callback).Run(Ok(), std::move(remote));
}

void CrossOriginStorageRegistry::CompleteCreateRequest(
    const url::Origin& origin,
    const CrossOriginStorageHash& hash,
    CrossOriginStorageScope scope,
    std::vector<url::Origin> origins,
    RequestFileHandleCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // A create request returns no information about prior state, so it is not a
  // fingerprinting oracle the way a read is. It is still real registry churn
  // and disk I/O, so it draws on a smaller, slower budget shared with the write
  // that normally follows it.
  if (!write_limiter_.TryConsume(origin)) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kOperationAborted,
              "Too many Cross-Origin Storage writes from this origin. Try "
              "again later."),
        mojo::NullRemote());
    return;
  }

  auto it = entries_.find(hash);
  if (it != entries_.end() && it->second.state ==
                                  CrossOriginStorageEntryState::kPending &&
      IsStale(it->second)) {
    // Replaced outright rather than adopted: the abandoned entry's outstanding
    // writer count and requested scope are no longer meaningful, and a new
    // writer must not inherit them.
    RemoveEntry(hash);
    it = entries_.end();
  }

  if (it == entries_.end()) {
    CrossOriginStorageEntry entry(hash);
    entry.created_at = base::Time::Now();
    entry.generation = next_generation_++;
    entry.scope = scope;
    if (scope == CrossOriginStorageScope::kList) {
      entry.origins = origins;
    }
    it = entries_.insert({hash, std::move(entry)}).first;
  }

  CrossOriginStorageEntry& entry = it->second;
  // Counts this handle as an outstanding writer even if the caller never calls
  // createWritable() on it. An abandoned handle then holds the entry pending
  // exactly as an abandoned in-flight write would, until the staleness timeout
  // reclaims it.
  ++entry.pending_writer_count;

  // The handle is returned whether or not the entry already existed, and
  // whether or not it is already written. The caller still has to supply the
  // complete bytes through it, so a create request cannot be used to detect
  // prior presence, and a request for a wider `origins` value is verified
  // before it is honored.
  auto handle = CrossOriginStorageFileHandleImpl::CreateForWrite(
      weak_factory_.GetWeakPtr(), origin, hash, entry.generation, scope,
      std::move(origins));
  mojo::PendingRemote<blink::mojom::FileSystemAccessFileHandle> remote;
  handles_.Add(std::move(handle), remote.InitWithNewPipeAndPassReceiver());
  std::move(callback).Run(Ok(), std::move(remote));
}

bool CrossOriginStorageRegistry::DetermineDisclosure(
    const CrossOriginStorageEntry& entry,
    const url::Origin& origin) {
  DCHECK_EQ(entry.state, CrossOriginStorageEntryState::kWritten);

  // An origin that has itself written these bytes can always read them back,
  // independent of the entry's scope and of the Public Hash List. This mirrors
  // the Cache API's model, where an origin always has access to what it stored.
  if (entry.IsStoringOrigin(origin)) {
    return true;
  }

  switch (entry.scope) {
    case CrossOriginStorageScope::kWildcard:
      // The PHL gate applies here and only here: "*" is the one case where
      // disclosure could otherwise reach any origin on the web. A list- or
      // same-site-scoped entry has already had its disclosure bounded by an
      // explicit choice of the storing origin, and requiring public curation on
      // top of that would make ordinary restricted sharing depend on a
      // proprietary resource appearing on a public allowlist.
      return public_hash_list_.Contains(entry.hash);

    case CrossOriginStorageScope::kList:
      // An explicit empty list is a real, empty list: it authorizes nobody but
      // the storing origins. It is not shorthand for the same-site default.
      return std::ranges::contains(entry.origins, origin);

    case CrossOriginStorageScope::kSameSite:
      return std::ranges::any_of(
          entry.storing_origins, [&origin](const url::Origin& storing) {
            return net::SchemefulSite(origin) == net::SchemefulSite(storing);
          });
  }
}

bool CrossOriginStorageRegistry::ApplyAvailabilityGating(
    const CrossOriginStorageEntry& entry,
    const url::Origin& origin) {
  if (!DetermineDisclosure(entry, origin)) {
    return false;
  }
  // A storing origin reads its own contribution back deterministically; adding
  // noise there would cost a re-download without telling an attacker anything
  // it did not already know by having supplied the bytes.
  if (entry.IsStoringOrigin(origin)) {
    return true;
  }
  return !ShouldGrease(entry);
}

bool CrossOriginStorageRegistry::ShouldGrease(
    const CrossOriginStorageEntry& entry) const {
  if (grease_disabled_for_testing_) {
    return false;
  }
  // Never GREASE a large entry. A false negative on a small file costs a cheap
  // re-fetch; on gigabyte-scale model weights it would impose a real, fully
  // observable bandwidth cost -- and that difference in cost is itself
  // detectable, which would undo the point of the noise.
  if (entry.size >= cos_constants::kGreaseSizeCeilingBytes) {
    return false;
  }
  // base::RandDouble() draws from the OS cryptographic RNG. A predictable roll
  // would not be noise at all: an adversary who can anticipate the gaps gets a
  // reliable presence signal back.
  return base::RandDouble() < cos_constants::kGreaseProbability;
}

void CrossOriginStorageRegistry::UpgradeResourceVisibility(
    CrossOriginStorageEntry& entry,
    CrossOriginStorageScope requested_scope,
    const std::vector<url::Origin>& requested) {
  // Omitting `origins` never narrows an entry: it asks only for same-site
  // availability, which every entry already has at least as much of.
  if (requested_scope == CrossOriginStorageScope::kSameSite) {
    return;
  }

  if (entry.scope == CrossOriginStorageScope::kWildcard) {
    if (requested_scope != CrossOriginStorageScope::kWildcard) {
      LOG(WARNING) << "Cross-Origin Storage: a resource that is already "
                      "globally available cannot be restricted by a later "
                      "write; the requested restriction was not applied.";
    }
    return;
  }

  if (requested_scope == CrossOriginStorageScope::kWildcard) {
    entry.scope = CrossOriginStorageScope::kWildcard;
    entry.origins.clear();
    return;
  }

  if (entry.scope == CrossOriginStorageScope::kSameSite) {
    entry.scope = CrossOriginStorageScope::kList;
    entry.origins = requested;
    return;
  }

  for (const url::Origin& candidate : requested) {
    if (std::ranges::contains(entry.origins, candidate)) {
      continue;
    }
    if (entry.origins.size() >= cos_constants::kMaxOriginsListLength) {
      // The write itself already succeeded -- the bytes were hashed, verified,
      // and stored -- so failing it now over a bookkeeping limit would discard
      // a potentially very large, already-verified write, and would not even be
      // attributable to a single caller's mistake. The excess origins are
      // dropped instead.
      LOG(WARNING) << "Cross-Origin Storage: the entry's origins list is at "
                      "capacity; additional origins were not added.";
      break;
    }
    entry.origins.push_back(candidate);
  }
}

bool CrossOriginStorageRegistry::IsStale(
    const CrossOriginStorageEntry& entry) const {
  return entry.state == CrossOriginStorageEntryState::kPending &&
         base::Time::Now() - entry.created_at >
             cos_constants::kPendingStalenessTimeout;
}

const CrossOriginStorageEntry* CrossOriginStorageRegistry::FindWrittenEntry(
    const CrossOriginStorageHash& hash) const {
  auto it = entries_.find(hash);
  if (it == entries_.end() ||
      it->second.state != CrossOriginStorageEntryState::kWritten) {
    return nullptr;
  }
  return &it->second;
}

CrossOriginStorageEntry* CrossOriginStorageRegistry::FindEntryForTesting(
    const CrossOriginStorageHash& hash) {
  auto it = entries_.find(hash);
  return it == entries_.end() ? nullptr : &it->second;
}

base::FilePath CrossOriginStorageRegistry::GetBytesPath(
    const CrossOriginStorageHash& hash) const {
  return root_directory_.Append(HashDirectoryComponent(hash))
      .Append(HashFileComponent(hash))
      .AddExtension(kBytesExtension);
}

base::FilePath CrossOriginStorageRegistry::GetMetadataPath(
    const CrossOriginStorageHash& hash) const {
  return root_directory_.Append(HashDirectoryComponent(hash))
      .Append(HashFileComponent(hash))
      .AddExtension(kMetadataExtension);
}

base::FilePath CrossOriginStorageRegistry::CreateSwapPath() {
  return root_directory_.Append(kSwapDirectoryName)
      .AppendASCII(base::Uuid::GenerateRandomV4().AsLowercaseString())
      .AddExtension(kTempExtension);
}

void CrossOriginStorageRegistry::AbandonWrite(
    const CrossOriginStorageHash& hash,
    uint64_t generation) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto it = entries_.find(hash);
  if (it == entries_.end() || it->second.generation != generation) {
    // The entry this writer belonged to is gone or has been replaced. Touching
    // whatever occupies the hash now would corrupt an unrelated write's
    // bookkeeping.
    return;
  }
  if (it->second.pending_writer_count > 0) {
    --it->second.pending_writer_count;
  }
  MaybeRemovePendingEntry(hash);
}

void CrossOriginStorageRegistry::MaybeRemovePendingEntry(
    const CrossOriginStorageHash& hash) {
  auto it = entries_.find(hash);
  if (it == entries_.end()) {
    return;
  }
  // Only an entry nobody has ever successfully written is eligible. Without
  // that qualifier, any origin could delete bytes another origin stored simply
  // by requesting a handle for the hash and writing garbage.
  if (it->second.state != CrossOriginStorageEntryState::kPending) {
    return;
  }
  // And only once no other writer is still outstanding, so that a failing
  // writer never deletes the entry a concurrent sibling write is about to
  // complete.
  if (it->second.pending_writer_count > 0) {
    return;
  }
  RemoveEntry(hash);
}

void CrossOriginStorageRegistry::RemoveEntry(
    const CrossOriginStorageHash& hash) {
  auto it = entries_.find(hash);
  if (it == entries_.end()) {
    return;
  }
  if (it->second.state == CrossOriginStorageEntryState::kWritten) {
    total_bytes_used_ -= it->second.size;
    if (it->second.attributed_origin) {
      auto usage = per_origin_bytes_used_.find(*it->second.attributed_origin);
      if (usage != per_origin_bytes_used_.end()) {
        usage->second -= it->second.size;
        if (usage->second <= 0) {
          per_origin_bytes_used_.erase(usage);
        }
      }
    }
    DeletePersistedEntry(hash);
  }
  entries_.erase(it);
}

void CrossOriginStorageRegistry::FinishWrite(
    const CrossOriginStorageHash& hash,
    uint64_t generation,
    const url::Origin& origin,
    CrossOriginStorageScope requested_scope,
    std::vector<url::Origin> requested_origins,
    const GURL& source_url,
    base::FilePath swap_path,
    int64_t size,
    const std::string& computed_value,
    WriteCompleteCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto it = entries_.find(hash);
  if (it == entries_.end() || it->second.generation != generation) {
    // The entry is gone or has been replaced; there is no writer count left to
    // settle, and the caller must not touch whatever occupies the hash now.
    file_runner_->PostTask(
        FROM_HERE, base::GetDeleteFileCallback(swap_path));
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "The Cross-Origin Storage entry is no longer available."));
    return;
  }

  // Reaching this point settles the writer either way, so it stops counting as
  // outstanding here rather than on each branch below. `MaybeRemovePendingEntry`
  // is what turns a definite failure into an ordinary absent hash, but only
  // once no sibling writer for the same hash is still in flight and only for an
  // entry nobody has ever successfully written.
  if (computed_value != hash.value()) {
    --it->second.pending_writer_count;
    MaybeRemovePendingEntry(hash);
    file_runner_->PostTask(
        FROM_HERE, base::GetDeleteFileCallback(swap_path));
    std::move(callback).Run(Error(
        blink::mojom::FileSystemAccessStatus::kDataError,
        "The written bytes do not hash to the requested value, so they were "
        "not stored in Cross-Origin Storage."));
    return;
  }

  // Content-addressability means a repeat write of identical bytes is free: the
  // entry already holds them, so nothing new is charged against quota. Only a
  // first successful store for this hash consumes budget.
  const bool already_written =
      it->second.state == CrossOriginStorageEntryState::kWritten;
  if (!already_written) {
    const int64_t usage = GetOriginUsage(origin);
    if (usage + size > per_origin_quota_bytes_) {
      // The reported limit is the stable nominal budget, never a number derived
      // from real free space: that would let a site infer live disk state by
      // triggering deliberate over-quota writes.
      --it->second.pending_writer_count;
      MaybeRemovePendingEntry(hash);
      file_runner_->PostTask(
          FROM_HERE, base::GetDeleteFileCallback(swap_path));
      LOG(WARNING) << "Cross-Origin Storage: this origin's write would exceed "
                      "its storage limit of "
                   << per_origin_quota_bytes_ << " bytes.";
      std::move(callback).Run(Error(
          blink::mojom::FileSystemAccessStatus::kQuotaExceededError,
          "Storing this file would exceed this origin's Cross-Origin Storage "
          "limit."));
      return;
    }
  }

  if (already_written) {
    // The bytes are already durably stored and verified identical, so there is
    // nothing to publish; only the bookkeeping below applies.
    file_runner_->PostTask(
        FROM_HERE, base::GetDeleteFileCallback(swap_path));
    OnBytesPublished(hash, generation, origin, requested_scope,
                     std::move(requested_origins), source_url, size,
                     std::move(callback), /*success=*/true);
    return;
  }

  base::FilePath bytes_path = GetBytesPath(hash);
  file_runner_->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(
          [](base::FilePath swap_path, base::FilePath bytes_path) {
            if (!base::CreateDirectory(bytes_path.DirName())) {
              base::DeleteFile(swap_path);
              return false;
            }
            // Renaming into place is what makes publication atomic: a reader
            // sees either no file or the complete one, never a torn write.
            if (!base::ReplaceFile(swap_path, bytes_path, nullptr)) {
              base::DeleteFile(swap_path);
              return false;
            }
            return true;
          },
          std::move(swap_path), std::move(bytes_path)),
      base::BindOnce(&CrossOriginStorageRegistry::OnBytesPublished,
                     weak_factory_.GetWeakPtr(), hash, generation, origin,
                     requested_scope, std::move(requested_origins), source_url,
                     size, std::move(callback)));
}

void CrossOriginStorageRegistry::OnBytesPublished(
    CrossOriginStorageHash hash,
    uint64_t generation,
    url::Origin origin,
    CrossOriginStorageScope requested_scope,
    std::vector<url::Origin> requested_origins,
    GURL source_url,
    int64_t size,
    WriteCompleteCallback callback,
    bool success) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto it = entries_.find(hash);
  if (it == entries_.end() || it->second.generation != generation) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "The Cross-Origin Storage entry is no longer available."));
    return;
  }

  // The write has settled, successfully or not, so it no longer counts as
  // outstanding.
  --it->second.pending_writer_count;

  if (!success) {
    MaybeRemovePendingEntry(hash);
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kOperationFailed,
              "Failed to store the file in Cross-Origin Storage."));
    return;
  }

  CrossOriginStorageEntry& entry = it->second;
  const bool first_write =
      entry.state != CrossOriginStorageEntryState::kWritten;
  if (first_write) {
    entry.state = CrossOriginStorageEntryState::kWritten;
    entry.size = size;
    entry.attributed_origin = origin;
    total_bytes_used_ += size;
    per_origin_bytes_used_[origin] += size;
    if (entry.last_read_at.is_null()) {
      entry.last_read_at = base::Time::Now();
    }
  }
  entry.AddStoringOrigin(origin);
  UpgradeResourceVisibility(entry, requested_scope, requested_origins);

  // Implementation-private provenance: never exposed to script by any COS API,
  // surfaced only through trusted, non-web surfaces, and presented as an
  // unverified claim by the writing origin rather than an attestation about the
  // bytes -- only the hash guarantees the content.
  // https://wicg.github.io/cross-origin-storage/#provenance-metadata
  auto existing = std::ranges::find_if(
      entry.provenance,
      [&origin](const CrossOriginStorageProvenanceRecord& record) {
        return record.origin == origin;
      });
  if (existing == entry.provenance.end()) {
    entry.provenance.emplace_back(origin, source_url, base::Time::Now());
  } else {
    existing->source_url = source_url;
    existing->recorded_at = base::Time::Now();
  }

  PersistEntry(entry);
  EnforceStorageBudget(origin);

  std::move(callback).Run(Ok());
}

int64_t CrossOriginStorageRegistry::GetOriginUsage(
    const url::Origin& origin) const {
  auto it = per_origin_bytes_used_.find(origin);
  return it == per_origin_bytes_used_.end() ? 0 : it->second;
}

void CrossOriginStorageRegistry::EnforceStorageBudget(
    const url::Origin& writing_origin) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Pass 1: if the writing origin is over its own share, it may only ever evict
  // its own sole-owned entries -- never a shared entry, even one it co-owns,
  // and never another origin's. One origin writing a lot must not be able to
  // force out a different origin's data merely by being more recent.
  auto collect_sorted = [this](auto predicate) {
    std::vector<CrossOriginStorageHash> candidates;
    for (const auto& [hash, entry] : entries_) {
      if (entry.state == CrossOriginStorageEntryState::kWritten &&
          predicate(entry)) {
        candidates.push_back(hash);
      }
    }
    // Oldest-read-first, not oldest-written-first: an entry a writer keeps
    // re-verifying but nobody ever reads should go before one actively serving
    // readers.
    std::ranges::sort(candidates, [this](const CrossOriginStorageHash& a,
                                         const CrossOriginStorageHash& b) {
      return entries_.at(a).last_read_at < entries_.at(b).last_read_at;
    });
    return candidates;
  };

  if (GetOriginUsage(writing_origin) > per_origin_quota_bytes_) {
    for (const auto& hash :
         collect_sorted([&writing_origin](const CrossOriginStorageEntry& e) {
           return e.storing_origins.size() == 1 &&
                  e.storing_origins.front() == writing_origin;
         })) {
      if (GetOriginUsage(writing_origin) <= per_origin_quota_bytes_) {
        break;
      }
      RemoveEntry(hash);
    }
  }

  // Pass 2: only when several origins, each within their own share, still
  // collectively exceed the global cap does eviction reach across origins.
  // That reflects genuine multi-tenant demand rather than one origin crowding
  // out another.
  if (total_bytes_used_ > global_quota_bytes_) {
    for (const auto& hash :
         collect_sorted([](const CrossOriginStorageEntry&) { return true; })) {
      if (total_bytes_used_ <= global_quota_bytes_) {
        break;
      }
      RemoveEntry(hash);
    }
  }
}

void CrossOriginStorageRegistry::PersistEntry(
    const CrossOriginStorageEntry& entry) {
  if (is_off_the_record_ ||
      entry.state != CrossOriginStorageEntryState::kWritten) {
    // A pending entry's bytes live only in its swap file until close()
    // succeeds. Losing an in-flight write across a crash is acceptable, and
    // costs no partial-write recovery logic.
    return;
  }
  base::Pickle pickle;
  SerializeEntry(entry, &pickle);
  const base::span<const uint8_t> bytes = pickle.AsBytes();
  std::vector<uint8_t> data(bytes.begin(), bytes.end());
  file_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](base::FilePath path, std::vector<uint8_t> data) {
            if (!base::CreateDirectory(path.DirName())) {
              return;
            }
            WriteFileAtomically(path, data);
          },
          GetMetadataPath(entry.hash), std::move(data)));
}

void CrossOriginStorageRegistry::DeletePersistedEntry(
    const CrossOriginStorageHash& hash) {
  file_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](base::FilePath bytes, base::FilePath meta) {
                       base::DeleteFile(bytes);
                       base::DeleteFile(meta);
                     },
                     GetBytesPath(hash), GetMetadataPath(hash)));
}

void CrossOriginStorageRegistry::ClearAllData(base::OnceClosure done) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  entries_.clear();
  total_bytes_used_ = 0;
  per_origin_bytes_used_.clear();
  read_limiter_.Clear();
  write_limiter_.Clear();

  base::FilePath root = root_directory_;
  file_runner_->PostTaskAndReply(
      FROM_HERE, base::BindOnce(
                     [](base::FilePath root) {
                       base::DeletePathRecursively(root);
                       base::CreateDirectory(root);
                       base::CreateDirectory(root.Append(kSwapDirectoryName));
                     },
                     root),
      std::move(done));
}

void CrossOriginStorageRegistry::ClearDataForOrigin(const url::Origin& origin,
                                                    base::OnceClosure done) {
  ClearDataWithFilter(
      base::BindRepeating(
          [](const url::Origin& target, const url::Origin& candidate) {
            return target == candidate;
          },
          origin),
      std::move(done));
}

void CrossOriginStorageRegistry::ClearDataWithFilter(
    base::RepeatingCallback<bool(const url::Origin&)> matcher,
    base::OnceClosure done) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  std::vector<url::Origin> cleared_origins;
  for (const auto& [candidate, unused] : per_origin_bytes_used_) {
    if (matcher.Run(candidate)) {
      cleared_origins.push_back(candidate);
    }
  }

  std::vector<CrossOriginStorageHash> to_remove;
  for (auto& [hash, entry] : entries_) {
    const size_t storing_before = entry.storing_origins.size();

    // Revoke rather than delete outright: an entry can have several storing
    // origins, and destroying data an uncleared site legitimately stored --
    // for an action that site was never part of -- is a worse outcome than the
    // cleared site's bytes persisting under a different, legitimate owner.
    auto matches = [&matcher](const url::Origin& candidate) {
      return matcher.Run(candidate);
    };
    std::erase_if(entry.storing_origins, matches);
    std::erase_if(entry.origins, matches);
    std::erase_if(entry.provenance,
                  [&matcher](const CrossOriginStorageProvenanceRecord& record) {
                    return matcher.Run(record.origin);
                  });

    if (entry.storing_origins.empty()) {
      // No origin has a storing relationship to these bytes left, so they go.
      to_remove.push_back(hash);
      continue;
    }
    if (entry.storing_origins.size() != storing_before) {
      PersistEntry(entry);
    }
  }
  for (const auto& hash : to_remove) {
    RemoveEntry(hash);
  }

  for (const auto& origin : cleared_origins) {
    read_limiter_.RemoveOrigin(origin);
    write_limiter_.RemoveOrigin(origin);
  }

  std::move(done).Run();
}

void CrossOriginStorageRegistry::WaitForInitializationForTesting() {
  if (initialized_) {
    return;
  }
  base::RunLoop run_loop;
  pending_initialization_callbacks_.push_back(run_loop.QuitClosure());
  run_loop.Run();
}

uint64_t CrossOriginStorageRegistry::AddWrittenEntryForTesting(
    const CrossOriginStorageHash& hash,
    int64_t size,
    CrossOriginStorageScope scope,
    std::vector<url::Origin> origins,
    std::vector<url::Origin> storing_origins) {
  CrossOriginStorageEntry entry(hash);
  entry.state = CrossOriginStorageEntryState::kWritten;
  entry.generation = next_generation_++;
  entry.size = size;
  entry.scope = scope;
  entry.origins = std::move(origins);
  entry.storing_origins = std::move(storing_origins);
  entry.created_at = base::Time::Now();
  entry.last_read_at = base::Time::Now();
  if (!entry.storing_origins.empty()) {
    entry.attributed_origin = entry.storing_origins.front();
    per_origin_bytes_used_[*entry.attributed_origin] += size;
  }
  total_bytes_used_ += size;

  const uint64_t generation = entry.generation;
  auto [it, inserted] = entries_.insert_or_assign(hash, std::move(entry));
  // Written through, as a real write would be, so that tests exercising a
  // restart see the same on-disk state a genuine write leaves behind.
  PersistEntry(it->second);
  return generation;
}

uint64_t CrossOriginStorageRegistry::AddPendingEntryForTesting(
    const CrossOriginStorageHash& hash,
    int pending_writer_count) {
  CrossOriginStorageEntry entry(hash);
  entry.state = CrossOriginStorageEntryState::kPending;
  entry.generation = next_generation_++;
  entry.pending_writer_count = pending_writer_count;
  entry.created_at = base::Time::Now();

  const uint64_t generation = entry.generation;
  entries_.insert_or_assign(hash, std::move(entry));
  return generation;
}

bool CrossOriginStorageRegistry::IsDisclosableForTesting(
    const CrossOriginStorageHash& hash,
    const url::Origin& origin) {
  auto it = entries_.find(hash);
  if (it == entries_.end() ||
      it->second.state != CrossOriginStorageEntryState::kWritten) {
    return false;
  }
  return ApplyAvailabilityGating(it->second, origin);
}

void CrossOriginStorageRegistry::UpgradeVisibilityForTesting(
    const CrossOriginStorageHash& hash,
    CrossOriginStorageScope requested_scope,
    const std::vector<url::Origin>& requested) {
  auto it = entries_.find(hash);
  CHECK(it != entries_.end());
  UpgradeResourceVisibility(it->second, requested_scope, requested);
}

base::WeakPtr<CrossOriginStorageRegistry>
CrossOriginStorageRegistry::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

}  // namespace content
