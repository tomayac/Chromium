// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_FILE_HANDLE_IMPL_H_
#define CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_FILE_HANDLE_IMPL_H_

#include <stdint.h>

#include <vector>

#include "base/memory/weak_ptr.h"
#include "base/sequence_checker.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_types.h"
#include "content/common/content_export.h"
#include "mojo/public/cpp/bindings/unique_receiver_set.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_handle.mojom.h"
#include "url/origin.h"

namespace content {

class CrossOriginStorageRegistry;

// A FileSystemFileHandle addressing a COS entry.
// https://wicg.github.io/cross-origin-storage/#cos-file-system
//
// Reusing the File System Standard's handle interface is what lets COS hand
// script an ordinary FileSystemFileHandle. Only the two operations that mean
// anything for a content-addressable entry are supported: getFile() and
// createWritable(). An entry has no name, no parent directory, and no identity
// apart from its hash, so renaming, moving, removing, and transferring it are
// all meaningless and are rejected.
//
// Handles are pre-authorized: the read or create request that produced one
// already ran every access-control and availability-gating check, so no
// operation here consults a permission prompt.
class CONTENT_EXPORT CrossOriginStorageFileHandleImpl
    : public blink::mojom::FileSystemAccessFileHandle {
 public:
  // Creates a handle for a read request. The entry was already found
  // disclosable to `origin`, so its bytes may be read immediately.
  static std::unique_ptr<CrossOriginStorageFileHandleImpl> CreateForRead(
      base::WeakPtr<CrossOriginStorageRegistry> registry,
      const url::Origin& origin,
      CrossOriginStorageHash hash);

  // Creates a handle for a create request. The caller must supply the complete
  // bytes through this very handle before it may read anything back, even if
  // the entry already exists and is written -- otherwise a create request would
  // be an oracle for whether a hash was already stored.
  static std::unique_ptr<CrossOriginStorageFileHandleImpl> CreateForWrite(
      base::WeakPtr<CrossOriginStorageRegistry> registry,
      const url::Origin& origin,
      CrossOriginStorageHash hash,
      uint64_t generation,
      CrossOriginStorageScope requested_scope,
      std::vector<url::Origin> requested_origins);

  CrossOriginStorageFileHandleImpl(
      const CrossOriginStorageFileHandleImpl&) = delete;
  CrossOriginStorageFileHandleImpl& operator=(
      const CrossOriginStorageFileHandleImpl&) = delete;
  ~CrossOriginStorageFileHandleImpl() override;

  // blink::mojom::FileSystemAccessFileHandle:
  void GetPermissionStatus(blink::mojom::FileSystemAccessPermissionMode mode,
                           GetPermissionStatusCallback callback) override;
  void RequestPermission(blink::mojom::FileSystemAccessPermissionMode mode,
                         RequestPermissionCallback callback) override;
  void AsBlob(AsBlobCallback callback) override;
  void CreateFileWriter(
      bool keep_existing_data,
      bool auto_close,
      blink::mojom::FileSystemAccessWritableFileStreamLockMode mode,
      CreateFileWriterCallback callback) override;
  void Rename(const std::string& new_entry_name,
              RenameCallback callback) override;
  void Move(mojo::PendingRemote<blink::mojom::FileSystemAccessTransferToken>
                destination_directory,
            const std::string& new_entry_name,
            MoveCallback callback) override;
  void Remove(RemoveCallback callback) override;
  void OpenAccessHandle(
      blink::mojom::FileSystemAccessAccessHandleLockMode mode,
      OpenAccessHandleCallback callback) override;
  void IsSameEntry(
      mojo::PendingRemote<blink::mojom::FileSystemAccessTransferToken> other,
      IsSameEntryCallback callback) override;
  void Transfer(
      mojo::PendingReceiver<blink::mojom::FileSystemAccessTransferToken> token)
      override;
  void GetUniqueId(GetUniqueIdCallback callback) override;
  void GetCloudIdentifiers(GetCloudIdentifiersCallback callback) override;

  // Called by the writer once this handle's own bytes have been verified and
  // stored, which is what makes the entry readable through this handle.
  void OnOwnWriteSucceeded();

  // Called by the writer when it has settled, successfully or not, so that this
  // handle no longer counts as an outstanding writer.
  void OnWriteSettled();

 private:
  CrossOriginStorageFileHandleImpl(
      base::WeakPtr<CrossOriginStorageRegistry> registry,
      const url::Origin& origin,
      CrossOriginStorageHash hash,
      uint64_t generation,
      bool writable,
      bool readable,
      CrossOriginStorageScope requested_scope,
      std::vector<url::Origin> requested_origins);

  void DidGetFileInfo(AsBlobCallback callback,
                      base::FilePath path,
                      std::optional<base::File::Info> info);

  SEQUENCE_CHECKER(sequence_checker_);

  base::WeakPtr<CrossOriginStorageRegistry> registry_;
  const url::Origin origin_;
  const CrossOriginStorageHash hash_;

  // Identifies the entry this handle was created against, so that a late
  // settle from an abandoned write cannot disturb an unrelated entry that
  // replaced it under the same hash.
  const uint64_t generation_;

  const bool writable_;

  // Whether getFile() may serve this entry's bytes. False for a create handle
  // until that handle's own write has verified and stored.
  bool readable_;

  const CrossOriginStorageScope requested_scope_;
  const std::vector<url::Origin> requested_origins_;

  bool writer_created_ = false;
  bool write_settled_ = false;

  mojo::UniqueReceiverSet<blink::mojom::FileSystemAccessFileWriter> writers_;

  base::WeakPtrFactory<CrossOriginStorageFileHandleImpl> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_FILE_HANDLE_IMPL_H_
