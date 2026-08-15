// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_MANAGER_IMPL_H_
#define CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_MANAGER_IMPL_H_

#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/common/content_export.h"
#include "content/public/browser/global_routing_id.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "third_party/blink/public/mojom/cross_origin_storage/cross_origin_storage.mojom.h"
#include "url/origin.h"

namespace content {

class BrowserContext;

// The browser end of navigator.crossOriginStorage, bound once per execution
// context (a document or a worker).
//
// The origin comes from the browser's own record of the binding context and is
// never taken from the pipe, so a compromised renderer cannot request another
// origin's entries by claiming to be it.
class CONTENT_EXPORT CrossOriginStorageManagerImpl
    : public blink::mojom::CrossOriginStorageManager {
 public:
  // `frame_id` identifies the document this binding belongs to, or is an
  // invalid id for a worker.
  static void Create(
      BrowserContext* browser_context,
      const url::Origin& origin,
      GlobalRenderFrameHostId frame_id,
      mojo::PendingReceiver<blink::mojom::CrossOriginStorageManager> receiver);

  CrossOriginStorageManagerImpl(const CrossOriginStorageManagerImpl&) = delete;
  CrossOriginStorageManagerImpl& operator=(
      const CrossOriginStorageManagerImpl&) = delete;
  ~CrossOriginStorageManagerImpl() override;

  // blink::mojom::CrossOriginStorageManager:
  void RequestFileHandle(blink::mojom::CrossOriginStorageHashPtr hash,
                         bool create,
                         blink::mojom::CrossOriginStorageScope scope,
                         const std::vector<url::Origin>& origins,
                         RequestFileHandleCallback callback) override;

 private:
  CrossOriginStorageManagerImpl(BrowserContext* browser_context,
                                const url::Origin& origin,
                                GlobalRenderFrameHostId frame_id);

  // Whether Permissions Policy allows this context to use the feature. The
  // renderer performs this check too, and its answer is the one the spec
  // describes; this is defense in depth for a renderer that does not.
  bool IsAllowedByPermissionsPolicy() const;

  const raw_ptr<BrowserContext> browser_context_;
  const url::Origin origin_;
  const GlobalRenderFrameHostId frame_id_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_CROSS_ORIGIN_STORAGE_CROSS_ORIGIN_STORAGE_MANAGER_IMPL_H_
