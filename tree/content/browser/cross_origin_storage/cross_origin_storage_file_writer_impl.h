// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_FILE_WRITER_IMPL_H_
#define CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_FILE_WRITER_IMPL_H_

#include <stdint.h>

#include <vector>

#include "base/files/file_path.h"
#include "base/memory/weak_ptr.h"
#include "base/sequence_checker.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_types.h"
#include "content/common/content_export.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_writer.mojom.h"
#include "url/origin.h"

namespace content {

class CrossOriginStorageFileHandleImpl;
class CrossOriginStorageRegistry;

// The write side of a COS entry: a FileSystemWritableFileStream backed by a
// swap file on disk.
//
// Two properties drive the design:
//
//   * A COS hash can only be verified against the complete, final byte
//     sequence. seek() and truncate() are genuine random-access edits that can
//     invalidate bytes already written, so hashing happens exactly once, over
//     the finished file at close() time, and never incrementally as writes
//     arrive.
//
//   * The payloads this feature targets are large -- multi-hundred-MiB model
//     shards are the normal case. The swap file is real disk from the start,
//     so a single truncate(huge) allocates disk rather than memory, and the
//     browser never holds a whole payload in RAM.
//
// https://wicg.github.io/cross-origin-storage/#creating-and-writing-files
class CONTENT_EXPORT CrossOriginStorageFileWriterImpl
    : public blink::mojom::FileSystemAccessFileWriter {
 public:
  CrossOriginStorageFileWriterImpl(
      base::WeakPtr<CrossOriginStorageRegistry> registry,
      base::WeakPtr<CrossOriginStorageFileHandleImpl> handle,
      const url::Origin& origin,
      CrossOriginStorageHash hash,
      uint64_t generation,
      CrossOriginStorageScope requested_scope,
      std::vector<url::Origin> requested_origins,
      base::FilePath swap_path);
  CrossOriginStorageFileWriterImpl(
      const CrossOriginStorageFileWriterImpl&) = delete;
  CrossOriginStorageFileWriterImpl& operator=(
      const CrossOriginStorageFileWriterImpl&) = delete;
  ~CrossOriginStorageFileWriterImpl() override;

  // blink::mojom::FileSystemAccessFileWriter:
  void Write(uint64_t offset,
             mojo::ScopedDataPipeConsumerHandle stream,
             WriteCallback callback) override;
  void Truncate(uint64_t length, TruncateCallback callback) override;
  void Close(CloseCallback callback) override;
  void Abort(AbortCallback callback) override;

 private:
  // Reads one chunk from the data pipe, writes it, and only then re-arms the
  // watcher. Waiting for each disk write before reading more is what keeps a
  // producer that outruns the disk from queueing unbounded pending chunks.
  void ReadFromPipe(MojoResult result, const mojo::HandleSignalsState& state);
  void OnChunkWritten(int64_t bytes_written_or_error);
  void FinishWrite(bool success);

  void OnTruncated(uint64_t length, bool success);
  void OnHashComputed(std::pair<std::string, int64_t> digest_and_size);
  void OnStoreComplete(blink::mojom::FileSystemAccessErrorPtr result);

  // Every terminal failure -- a hash mismatch, a disk I/O error, a breach of
  // the streaming size cap, or an abort -- funnels through here, so there is
  // exactly one cleanup path rather than one per failure mode.
  void FailTerminally(blink::mojom::FileSystemAccessErrorPtr error);

  // Records that this writer no longer counts as one of the entry's outstanding
  // writers. Idempotent, because the same writer can reach this through a
  // failed close(), an explicit abort(), and its own destructor.
  //
  // `abandon` tells the registry to do the decrement. It must be false whenever
  // the registry already decremented as part of finishing the write, or an
  // entry would be released while a genuinely concurrent sibling writer is
  // still in flight.
  void MarkSettled(bool abandon);

  // Deletes the swap file, unless ownership of it has already passed to the
  // registry. Safe to call more than once.
  void Cleanup();

  SEQUENCE_CHECKER(sequence_checker_);

  base::WeakPtr<CrossOriginStorageRegistry> registry_;
  base::WeakPtr<CrossOriginStorageFileHandleImpl> handle_;
  const url::Origin origin_;
  const CrossOriginStorageHash hash_;
  const uint64_t generation_;
  const CrossOriginStorageScope requested_scope_;
  const std::vector<url::Origin> requested_origins_;

  base::FilePath swap_path_;
  bool settled_ = false;

  // The swap file's current logical size, tracked here so the streaming size
  // cap can be checked before a resize is attempted rather than after, and
  // without a syscall per chunk.
  int64_t current_size_ = 0;

  // Set if any chunk failed to reach disk. Checked first at close() time,
  // before the digest is trusted: the digest is computed from the finished
  // file, but a partial write elsewhere would otherwise be invisible.
  bool had_write_error_ = false;

  // In-progress Write().
  mojo::ScopedDataPipeConsumerHandle pipe_;
  std::unique_ptr<mojo::SimpleWatcher> pipe_watcher_;
  WriteCallback write_callback_;
  uint64_t write_offset_ = 0;
  uint64_t bytes_written_ = 0;

  CloseCallback close_callback_;

  base::WeakPtrFactory<CrossOriginStorageFileWriterImpl> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_FILE_WRITER_IMPL_H_
