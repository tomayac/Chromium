// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_MANAGER_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_MANAGER_H_

#include "third_party/blink/public/mojom/cross_origin_storage/cross_origin_storage.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/modules/modules_export.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/supplementable.h"

namespace blink {

class CrossOriginStorageRequestFileHandleHash;
class CrossOriginStorageRequestFileHandleOptions;
class ExceptionState;
class FileSystemFileHandle;
class NavigatorBase;
class ScriptState;

// navigator.crossOriginStorage, the entry point into Cross-Origin Storage
// (COS): a browser-wide, content-addressable cache shared across origins.
// https://wicg.github.io/cross-origin-storage/
//
// This class is a thin IPC client. It performs the spec's Permissions Policy
// gate and "validate a COS request" checks so that malformed input is rejected
// without a round trip, then forwards to the browser process, which owns the
// registry and independently re-validates everything it is sent.
class MODULES_EXPORT CrossOriginStorageManager final
    : public ScriptWrappable,
      public Supplement<NavigatorBase> {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static const char kSupplementName[];

  // Web-exposed as navigator.crossOriginStorage.
  static CrossOriginStorageManager* crossOriginStorage(NavigatorBase&);

  explicit CrossOriginStorageManager(NavigatorBase&);

  CrossOriginStorageManager(const CrossOriginStorageManager&) = delete;
  CrossOriginStorageManager& operator=(const CrossOriginStorageManager&) =
      delete;

  ScriptPromise<FileSystemFileHandle> requestFileHandle(
      ScriptState*,
      const CrossOriginStorageRequestFileHandleHash* hash,
      const CrossOriginStorageRequestFileHandleOptions* options,
      ExceptionState&);

  void Trace(Visitor*) const override;

 private:
  // Lazily binds `remote_`. Returns false if the execution context is gone.
  bool EnsureRemote(ExecutionContext*);

  void OnRequestFileHandleResult(
      ScriptPromiseResolver<FileSystemFileHandle>*,
      const String& name,
      mojom::blink::FileSystemAccessErrorPtr result,
      mojo::PendingRemote<mojom::blink::FileSystemAccessFileHandle> handle);

  HeapMojoRemote<mojom::blink::CrossOriginStorageManager> remote_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_MANAGER_H_
