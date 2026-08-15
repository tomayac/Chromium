// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_file_writer_impl.h"

#include <utility>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_file_handle_impl.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_registry.h"
#include "crypto/hash.h"

namespace content {

namespace {

// Bounded so that one read never allocates more than this, regardless of how
// much the producer has queued.
constexpr size_t kChunkSize = 512 * 1024;

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

// Writes `data` at `offset`, creating the file if needed. Returns the number of
// bytes written, or a negative value on failure.
int64_t WriteChunkToSwapFile(const base::FilePath& path,
                             int64_t offset,
                             std::vector<uint8_t> data) {
  base::File file(path, base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_WRITE);
  if (!file.IsValid()) {
    return -1;
  }
  const std::optional<size_t> written = file.Write(offset, data);
  if (!written || *written != data.size()) {
    return -1;
  }
  return static_cast<int64_t>(*written);
}

bool TruncateSwapFile(const base::FilePath& path, int64_t length) {
  base::File file(path, base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_WRITE);
  if (!file.IsValid()) {
    return false;
  }
  return file.SetLength(length);
}

// Hashes the finished swap file sequentially and returns (lowercase hex digest,
// size). Returns an empty digest if the file cannot be read.
//
// This runs once, over the final contents, rather than incrementally as writes
// arrived: seek() and truncate() are genuine random-access edits, so bytes
// already seen can still be overwritten or dropped before close().
std::pair<std::string, int64_t> HashSwapFile(const base::FilePath& path,
                                             const std::string& algorithm) {
  std::optional<crypto::hash::HashKind> kind;
  if (algorithm == "SHA-256") {
    kind = crypto::hash::kSha256;
  } else if (algorithm == "SHA-1") {
    kind = crypto::hash::kSha1;
  } else if (algorithm == "SHA-384") {
    kind = crypto::hash::kSha384;
  } else if (algorithm == "SHA-512") {
    kind = crypto::hash::kSha512;
  }
  if (!kind) {
    return {std::string(), 0};
  }

  base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid()) {
    return {std::string(), 0};
  }
  const int64_t size = file.GetLength();
  if (size < 0) {
    return {std::string(), 0};
  }

  std::vector<uint8_t> digest(crypto::hash::DigestSizeForHashKind(*kind));
  if (!crypto::hash::HashFile(*kind, &file, digest)) {
    return {std::string(), 0};
  }
  return {base::ToLowerASCII(base::HexEncode(digest)), size};
}

}  // namespace

CrossOriginStorageFileWriterImpl::CrossOriginStorageFileWriterImpl(
    base::WeakPtr<CrossOriginStorageRegistry> registry,
    base::WeakPtr<CrossOriginStorageFileHandleImpl> handle,
    const url::Origin& origin,
    CrossOriginStorageHash hash,
    uint64_t generation,
    CrossOriginStorageScope requested_scope,
    std::vector<url::Origin> requested_origins,
    base::FilePath swap_path)
    : registry_(std::move(registry)),
      handle_(std::move(handle)),
      origin_(origin),
      hash_(std::move(hash)),
      generation_(generation),
      requested_scope_(requested_scope),
      requested_origins_(std::move(requested_origins)),
      swap_path_(std::move(swap_path)) {}

CrossOriginStorageFileWriterImpl::~CrossOriginStorageFileWriterImpl() {
  // Reaching the destructor without having settled means the renderer dropped
  // the pipe -- which is how the File System Standard's abort() surfaces here,
  // and also what a crashed or navigated-away page looks like. Either way this
  // write will never succeed, so it must stop holding the entry pending.
  MarkSettled(/*abandon=*/true);
  Cleanup();
}

void CrossOriginStorageFileWriterImpl::Write(
    uint64_t offset,
    mojo::ScopedDataPipeConsumerHandle stream,
    WriteCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (settled_ || write_callback_) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "The writable stream is not in a state to accept writes."),
        0);
    return;
  }

  // Checked before anything is written rather than after: a single
  // seek(huge) + write() would otherwise claim an arbitrary amount of disk
  // immediately, long before the authoritative budget check at close().
  if (static_cast<int64_t>(offset) > cos_constants::kStreamingSizeCapBytes) {
    had_write_error_ = true;
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kQuotaExceededError,
              "The write exceeds the maximum size of a single Cross-Origin "
              "Storage file."),
        0);
    return;
  }

  pipe_ = std::move(stream);
  write_callback_ = std::move(callback);
  write_offset_ = offset;
  bytes_written_ = 0;

  pipe_watcher_ = std::make_unique<mojo::SimpleWatcher>(
      FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL,
      base::SequencedTaskRunner::GetCurrentDefault());
  pipe_watcher_->Watch(
      pipe_.get(), MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
      base::BindRepeating(&CrossOriginStorageFileWriterImpl::ReadFromPipe,
                          weak_factory_.GetWeakPtr()));
  ReadFromPipe(MOJO_RESULT_OK, mojo::HandleSignalsState());
}

void CrossOriginStorageFileWriterImpl::ReadFromPipe(
    MojoResult result,
    const mojo::HandleSignalsState& state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!write_callback_) {
    return;
  }

  base::span<const uint8_t> buffer;
  const MojoResult read_result =
      pipe_->BeginReadData(MOJO_READ_DATA_FLAG_NONE, buffer);

  if (read_result == MOJO_RESULT_SHOULD_WAIT) {
    pipe_watcher_->ArmOrNotify();
    return;
  }
  if (read_result == MOJO_RESULT_FAILED_PRECONDITION) {
    // The producer finished and closed its end: everything it sent has been
    // written.
    FinishWrite(/*success=*/true);
    return;
  }
  if (read_result != MOJO_RESULT_OK) {
    FinishWrite(/*success=*/false);
    return;
  }

  const size_t chunk_size = std::min(buffer.size(), kChunkSize);
  std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + chunk_size);
  pipe_->EndReadData(chunk_size);

  const int64_t chunk_end =
      static_cast<int64_t>(write_offset_ + bytes_written_) +
      static_cast<int64_t>(chunk.size());
  if (chunk_end > cos_constants::kStreamingSizeCapBytes) {
    had_write_error_ = true;
    FinishWrite(/*success=*/false);
    return;
  }

  if (!registry_) {
    FinishWrite(/*success=*/false);
    return;
  }

  // The watcher is deliberately not re-armed until this write lands. Reading
  // ahead of the disk would let a producer that outruns it queue unbounded
  // pending chunks in memory, which is exactly what a disk-backed swap file is
  // supposed to prevent.
  registry_->file_runner()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&WriteChunkToSwapFile, swap_path_,
                     static_cast<int64_t>(write_offset_ + bytes_written_),
                     std::move(chunk)),
      base::BindOnce(&CrossOriginStorageFileWriterImpl::OnChunkWritten,
                     weak_factory_.GetWeakPtr()));
}

void CrossOriginStorageFileWriterImpl::OnChunkWritten(
    int64_t bytes_written_or_error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!write_callback_) {
    return;
  }

  if (bytes_written_or_error < 0) {
    // Recorded explicitly rather than inferred later. The digest at close() is
    // computed from what actually landed on disk, but a caller could still be
    // told a truncated write succeeded if this were only logged; the flag is
    // checked first, ahead of the digest.
    had_write_error_ = true;
    FinishWrite(/*success=*/false);
    return;
  }

  bytes_written_ += static_cast<uint64_t>(bytes_written_or_error);
  current_size_ = std::max(
      current_size_, static_cast<int64_t>(write_offset_ + bytes_written_));
  ReadFromPipe(MOJO_RESULT_OK, mojo::HandleSignalsState());
}

void CrossOriginStorageFileWriterImpl::FinishWrite(bool success) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  pipe_watcher_.reset();
  pipe_.reset();

  WriteCallback callback = std::move(write_callback_);
  if (!callback) {
    return;
  }
  if (success) {
    std::move(callback).Run(Ok(), bytes_written_);
    return;
  }
  std::move(callback).Run(
      Error(blink::mojom::FileSystemAccessStatus::kOperationFailed,
            "Failed to write to Cross-Origin Storage."),
      bytes_written_);
}

void CrossOriginStorageFileWriterImpl::Truncate(uint64_t length,
                                                TruncateCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (settled_ || write_callback_) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "The writable stream is not in a state to be truncated."));
    return;
  }

  // truncate() sets the file's size directly, without a single byte crossing
  // the wire, so it is the cheapest way to claim disk. The cap is therefore
  // checked before the resize is attempted, not after.
  if (static_cast<int64_t>(length) > cos_constants::kStreamingSizeCapBytes) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kQuotaExceededError,
              "Truncating to " + base::NumberToString(length) +
                  " bytes exceeds the maximum size of a single Cross-Origin "
                  "Storage file."));
    return;
  }

  if (!registry_) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "Cross-Origin Storage is no longer available."));
    return;
  }

  registry_->file_runner()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&TruncateSwapFile, swap_path_,
                     static_cast<int64_t>(length)),
      base::BindOnce(
          [](base::WeakPtr<CrossOriginStorageFileWriterImpl> self,
             uint64_t length, TruncateCallback callback, bool success) {
            if (self && success) {
              self->current_size_ = static_cast<int64_t>(length);
            }
            if (!success && self) {
              self->had_write_error_ = true;
            }
            std::move(callback).Run(
                success ? Ok()
                        : Error(blink::mojom::FileSystemAccessStatus::
                                    kOperationFailed,
                                "Failed to resize the file."));
          },
          weak_factory_.GetWeakPtr(), length, std::move(callback)));
}

void CrossOriginStorageFileWriterImpl::Close(CloseCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (settled_ || close_callback_ || write_callback_) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "The writable stream is not in a state to be closed."));
    return;
  }

  // Checked before the digest, and ahead of anything else: a chunk that never
  // reached disk cannot be detected by hashing the file, because the file's
  // contents are exactly what did land there.
  if (had_write_error_) {
    close_callback_ = std::move(callback);
    FailTerminally(
        Error(blink::mojom::FileSystemAccessStatus::kOperationFailed,
              "The file could not be written to Cross-Origin Storage."));
    return;
  }

  if (!registry_) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "Cross-Origin Storage is no longer available."));
    return;
  }

  close_callback_ = std::move(callback);
  registry_->file_runner()->PostTaskAndReplyWithResult(
      FROM_HERE, base::BindOnce(&HashSwapFile, swap_path_, hash_.algorithm()),
      base::BindOnce(&CrossOriginStorageFileWriterImpl::OnHashComputed,
                     weak_factory_.GetWeakPtr()));
}

void CrossOriginStorageFileWriterImpl::OnHashComputed(
    std::pair<std::string, int64_t> digest_and_size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const std::string& computed = digest_and_size.first;
  const int64_t size = digest_and_size.second;

  if (computed.empty()) {
    FailTerminally(
        Error(blink::mojom::FileSystemAccessStatus::kOperationFailed,
              "The file could not be read back for verification."));
    return;
  }
  if (!registry_) {
    FailTerminally(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "Cross-Origin Storage is no longer available."));
    return;
  }

  base::FilePath swap_path = swap_path_;
  // Cleared so the destructor and cleanup paths no longer treat this swap file
  // as theirs to delete; ownership passes to the registry, which either
  // publishes it or discards it.
  swap_path_ = base::FilePath();

  registry_->FinishWrite(
      hash_, generation_, origin_, requested_scope_, requested_origins_,
      // The imperative API never names a source URL. The declarative
      // integrations, which fetch from a URL the user agent itself chose, are
      // where a meaningful provenance claim will come from.
      GURL(), std::move(swap_path), size, computed,
      base::BindOnce(&CrossOriginStorageFileWriterImpl::OnStoreComplete,
                     weak_factory_.GetWeakPtr()));
}

void CrossOriginStorageFileWriterImpl::OnStoreComplete(
    blink::mojom::FileSystemAccessErrorPtr result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const bool succeeded =
      result->status == blink::mojom::FileSystemAccessStatus::kOk;
  if (succeeded && handle_) {
    // Only now may this handle read the entry back. Requiring the caller to
    // have supplied the bytes first is what stops a create request from
    // revealing whether the hash was already stored.
    handle_->OnOwnWriteSucceeded();
  }

  // The registry already accounted for this writer as part of finishing, so
  // settling here must not decrement a second time -- doing so could release an
  // entry a genuinely concurrent sibling writer is still working on.
  MarkSettled(/*abandon=*/false);
  Cleanup();

  if (close_callback_) {
    std::move(close_callback_).Run(std::move(result));
  }
}

void CrossOriginStorageFileWriterImpl::FailTerminally(
    blink::mojom::FileSystemAccessErrorPtr error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Abandoning here is what lets a later requestFileHandle() for this hash get
  // an ordinary "not found" rather than being stuck reporting an in-progress
  // write forever -- but only if no sibling writer for the same hash is still
  // outstanding, which the registry checks.
  MarkSettled(/*abandon=*/true);
  Cleanup();

  if (close_callback_) {
    std::move(close_callback_).Run(std::move(error));
  }
}

void CrossOriginStorageFileWriterImpl::Abort(AbortCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  MarkSettled(/*abandon=*/true);
  Cleanup();
  std::move(callback).Run(Ok());
}

void CrossOriginStorageFileWriterImpl::MarkSettled(bool abandon) {
  if (settled_) {
    return;
  }
  settled_ = true;
  if (handle_) {
    handle_->OnWriteSettled();
  }
  if (abandon && registry_) {
    registry_->AbandonWrite(hash_, generation_);
  }
}

void CrossOriginStorageFileWriterImpl::Cleanup() {
  // Empty once ownership of the swap file has passed to the registry, which
  // either publishes it or discards it itself.
  if (!swap_path_.empty() && registry_) {
    registry_->file_runner()->PostTask(
        FROM_HERE,
        base::GetDeleteFileCallback(swap_path_));
  }
  swap_path_ = base::FilePath();
}

}  // namespace content
