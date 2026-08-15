// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_file_handle_impl.h"

#include <utility>

#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/task/bind_post_task.h"
#include "base/uuid.h"
#include "content/browser/blob_storage/chrome_blob_storage_context.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_file_writer_impl.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_registry.h"
#include "content/public/browser/browser_thread.h"
#include "third_party/blink/public/mojom/blob/blob.mojom.h"
#include "third_party/blink/public/mojom/blob/serialized_blob.mojom.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_access_handle_host.mojom.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_cloud_identifier.mojom.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_writer.mojom.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_transfer_token.mojom.h"

namespace content {

namespace {

blink::mojom::FileSystemAccessErrorPtr Error(
    blink::mojom::FileSystemAccessStatus status,
    std::string message) {
  return blink::mojom::FileSystemAccessError::New(status, base::File::FILE_OK,
                                                  std::move(message));
}

blink::mojom::FileSystemAccessErrorPtr NotSupported() {
  return Error(blink::mojom::FileSystemAccessStatus::kNotSupportedError,
               "This operation is not supported on a Cross-Origin Storage "
               "file handle.");
}

}  // namespace

// static
std::unique_ptr<CrossOriginStorageFileHandleImpl>
CrossOriginStorageFileHandleImpl::CreateForRead(
    base::WeakPtr<CrossOriginStorageRegistry> registry,
    const url::Origin& origin,
    CrossOriginStorageHash hash) {
  return base::WrapUnique(new CrossOriginStorageFileHandleImpl(
      std::move(registry), origin, std::move(hash), /*generation=*/0,
      /*writable=*/false, /*readable=*/true,
      CrossOriginStorageScope::kSameSite, /*requested_origins=*/{}));
}

// static
std::unique_ptr<CrossOriginStorageFileHandleImpl>
CrossOriginStorageFileHandleImpl::CreateForWrite(
    base::WeakPtr<CrossOriginStorageRegistry> registry,
    const url::Origin& origin,
    CrossOriginStorageHash hash,
    uint64_t generation,
    CrossOriginStorageScope requested_scope,
    std::vector<url::Origin> requested_origins) {
  return base::WrapUnique(new CrossOriginStorageFileHandleImpl(
      std::move(registry), origin, std::move(hash), generation,
      /*writable=*/true, /*readable=*/false, requested_scope,
      std::move(requested_origins)));
}

CrossOriginStorageFileHandleImpl::CrossOriginStorageFileHandleImpl(
    base::WeakPtr<CrossOriginStorageRegistry> registry,
    const url::Origin& origin,
    CrossOriginStorageHash hash,
    uint64_t generation,
    bool writable,
    bool readable,
    CrossOriginStorageScope requested_scope,
    std::vector<url::Origin> requested_origins)
    : registry_(std::move(registry)),
      origin_(origin),
      hash_(std::move(hash)),
      generation_(generation),
      writable_(writable),
      readable_(readable),
      requested_scope_(requested_scope),
      requested_origins_(std::move(requested_origins)) {}

CrossOriginStorageFileHandleImpl::~CrossOriginStorageFileHandleImpl() {
  // A create handle that is dropped without its write ever settling -- the page
  // navigated away, or script simply never called createWritable() and let the
  // handle be collected -- stops counting as an outstanding writer here, so it
  // does not have to wait out the staleness timeout.
  if (writable_ && !write_settled_ && registry_) {
    registry_->AbandonWrite(hash_, generation_);
  }
}

void CrossOriginStorageFileHandleImpl::GetPermissionStatus(
    blink::mojom::FileSystemAccessPermissionMode mode,
    GetPermissionStatusCallback callback) {
  // Handles from this file system are authorized when they are handed out, so
  // there is no per-call permission state to consult.
  std::move(callback).Run(blink::mojom::PermissionStatus::GRANTED);
}

void CrossOriginStorageFileHandleImpl::RequestPermission(
    blink::mojom::FileSystemAccessPermissionMode mode,
    RequestPermissionCallback callback) {
  std::move(callback).Run(
      blink::mojom::FileSystemAccessError::New(
          blink::mojom::FileSystemAccessStatus::kOk, base::File::FILE_OK, ""),
      blink::mojom::PermissionStatus::GRANTED);
}

void CrossOriginStorageFileHandleImpl::AsBlob(AsBlobCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!readable_) {
    // A create handle cannot read until its own write has verified and stored.
    // Serving an entry some other origin wrote here would make a create request
    // an oracle for whether the hash was already present, bypassing every
    // access-control and availability-gating check the read path applies.
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kPermissionDenied,
              "This handle's file has not been written yet."),
        base::File::Info(), nullptr);
    return;
  }

  if (!registry_) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "Cross-Origin Storage is no longer available."),
        base::File::Info(), nullptr);
    return;
  }

  const CrossOriginStorageEntry* entry = registry_->FindWrittenEntry(hash_);
  if (!entry) {
    // The entry was evicted or cleared after this handle was authorized.
    std::move(callback).Run(
        blink::mojom::FileSystemAccessError::New(
            blink::mojom::FileSystemAccessStatus::kFileError,
            base::File::FILE_ERROR_NOT_FOUND,
            "The file is no longer in Cross-Origin Storage."),
        base::File::Info(), nullptr);
    return;
  }

  base::FilePath path = registry_->GetBytesPath(hash_);
  registry_->file_runner()->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(
          [](base::FilePath path) -> std::optional<base::File::Info> {
            base::File::Info info;
            if (!base::GetFileInfo(path, &info)) {
              return std::nullopt;
            }
            return info;
          },
          path),
      base::BindOnce(&CrossOriginStorageFileHandleImpl::DidGetFileInfo,
                     weak_factory_.GetWeakPtr(), std::move(callback),
                     std::move(path)));
}

void CrossOriginStorageFileHandleImpl::DidGetFileInfo(
    AsBlobCallback callback,
    base::FilePath path,
    std::optional<base::File::Info> info) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!info) {
    std::move(callback).Run(
        blink::mojom::FileSystemAccessError::New(
            blink::mojom::FileSystemAccessStatus::kFileError,
            base::File::FILE_ERROR_NOT_FOUND,
            "The file is no longer in Cross-Origin Storage."),
        base::File::Info(), nullptr);
    return;
  }

  ChromeBlobStorageContext* blob_context =
      registry_ && registry_->browser_context()
          ? ChromeBlobStorageContext::GetFor(registry_->browser_context())
          : nullptr;
  if (!blob_context) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "Cross-Origin Storage is no longer available."),
        base::File::Info(), nullptr);
    return;
  }

  std::string uuid = base::Uuid::GenerateRandomV4().AsLowercaseString();
  // A COS entry is an opaque byte sequence identified by its hash. Nothing
  // about it names a file type, and guessing one from the hash is impossible,
  // so the blob carries no content type.
  std::string content_type;

  mojo::PendingRemote<blink::mojom::Blob> blob_remote;
  mojo::PendingReceiver<blink::mojom::Blob> blob_receiver =
      blob_remote.InitWithNewPipeAndPassReceiver();

  std::move(callback).Run(
      blink::mojom::FileSystemAccessError::New(
          blink::mojom::FileSystemAccessStatus::kOk, base::File::FILE_OK, ""),
      *info,
      blink::mojom::SerializedBlob::New(uuid, content_type, info->size,
                                        std::move(blob_remote)));

  // File-backed rather than memory-backed: these payloads are routinely large
  // enough that materializing one to hand script a Blob would be a problem in
  // itself.
  GetIOThreadTaskRunner({})->PostTask(
      FROM_HERE,
      base::BindOnce(&ChromeBlobStorageContext::CreateFileBackedBlob,
                     base::WrapRefCounted(blob_context),
                     std::move(blob_receiver), std::move(path),
                     std::move(uuid), std::move(content_type), info->size,
                     info->last_modified));
}

void CrossOriginStorageFileHandleImpl::CreateFileWriter(
    bool keep_existing_data,
    bool auto_close,
    blink::mojom::FileSystemAccessWritableFileStreamLockMode mode,
    CreateFileWriterCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!writable_) {
    // A handle obtained from a read was never counted as an outstanding writer,
    // so letting it write would leave the entry's bookkeeping inconsistent.
    // Writing needs a create request.
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kPermissionDenied,
              "This handle was not obtained with create: true, so it cannot "
              "be written to."),
        mojo::NullRemote());
    return;
  }
  if (writer_created_) {
    // The entry counts writers by handle, so a second writer on the same handle
    // would not be accounted for.
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "A writable stream has already been created for this handle."),
        mojo::NullRemote());
    return;
  }
  if (!registry_) {
    std::move(callback).Run(
        Error(blink::mojom::FileSystemAccessStatus::kInvalidState,
              "Cross-Origin Storage is no longer available."),
        mojo::NullRemote());
    return;
  }

  writer_created_ = true;

  auto writer = std::make_unique<CrossOriginStorageFileWriterImpl>(
      registry_, weak_factory_.GetWeakPtr(), origin_, hash_, generation_,
      requested_scope_, requested_origins_, registry_->CreateSwapPath());
  mojo::PendingRemote<blink::mojom::FileSystemAccessFileWriter> remote;
  writers_.Add(std::move(writer), remote.InitWithNewPipeAndPassReceiver());
  std::move(callback).Run(
      blink::mojom::FileSystemAccessError::New(
          blink::mojom::FileSystemAccessStatus::kOk, base::File::FILE_OK, ""),
      std::move(remote));
}

void CrossOriginStorageFileHandleImpl::OnOwnWriteSucceeded() {
  readable_ = true;
}

void CrossOriginStorageFileHandleImpl::OnWriteSettled() {
  write_settled_ = true;
}

// A COS entry has no name, no containing directory, and no identity apart from
// its hash, so none of the File System Standard's structural operations mean
// anything for one.
void CrossOriginStorageFileHandleImpl::Rename(const std::string& new_entry_name,
                                              RenameCallback callback) {
  std::move(callback).Run(NotSupported());
}

void CrossOriginStorageFileHandleImpl::Move(
    mojo::PendingRemote<blink::mojom::FileSystemAccessTransferToken>
        destination_directory,
    const std::string& new_entry_name,
    MoveCallback callback) {
  std::move(callback).Run(NotSupported());
}

void CrossOriginStorageFileHandleImpl::Remove(RemoveCallback callback) {
  // Deliberately unsupported rather than implemented: an entry is shared by
  // every origin that stored it, so letting any one of them delete it would let
  // a site destroy data other sites depend on. Removal belongs to eviction and
  // to the user's own storage controls.
  std::move(callback).Run(NotSupported());
}

void CrossOriginStorageFileHandleImpl::OpenAccessHandle(
    blink::mojom::FileSystemAccessAccessHandleLockMode mode,
    OpenAccessHandleCallback callback) {
  // A sync access handle hands the renderer a writable OS file descriptor,
  // which would let it change an entry's bytes out from under the hash they are
  // stored against.
  std::move(callback).Run(NotSupported(), nullptr, mojo::NullRemote());
}

void CrossOriginStorageFileHandleImpl::IsSameEntry(
    mojo::PendingRemote<blink::mojom::FileSystemAccessTransferToken> other,
    IsSameEntryCallback callback) {
  std::move(callback).Run(NotSupported(), false);
}

void CrossOriginStorageFileHandleImpl::Transfer(
    mojo::PendingReceiver<blink::mojom::FileSystemAccessTransferToken> token) {
  // Dropping the receiver leaves the token unbound, which is how a
  // non-transferable handle reports itself.
}

void CrossOriginStorageFileHandleImpl::GetUniqueId(
    GetUniqueIdCallback callback) {
  std::move(callback).Run(NotSupported(), std::string());
}

void CrossOriginStorageFileHandleImpl::GetCloudIdentifiers(
    GetCloudIdentifiersCallback callback) {
  std::move(callback).Run(NotSupported(), {});
}

}  // namespace content
