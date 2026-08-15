// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_manager_impl.h"

#include <utility>

#include "content/browser/cross_origin_storage/cross_origin_storage_registry.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/render_frame_host.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "services/network/public/mojom/permissions_policy/permissions_policy_feature.mojom.h"

namespace content {

namespace {

CrossOriginStorageScope ToScope(blink::mojom::CrossOriginStorageScope scope) {
  switch (scope) {
    case blink::mojom::CrossOriginStorageScope::kSameSite:
      return CrossOriginStorageScope::kSameSite;
    case blink::mojom::CrossOriginStorageScope::kList:
      return CrossOriginStorageScope::kList;
    case blink::mojom::CrossOriginStorageScope::kWildcard:
      return CrossOriginStorageScope::kWildcard;
  }
}

}  // namespace

// static
void CrossOriginStorageManagerImpl::Create(
    BrowserContext* browser_context,
    const url::Origin& origin,
    GlobalRenderFrameHostId frame_id,
    mojo::PendingReceiver<blink::mojom::CrossOriginStorageManager> receiver) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  // An opaque origin has no stable identity to key storing origins or same-site
  // comparisons on, so it gets no access at all rather than an origin that
  // silently matches nothing.
  if (origin.opaque()) {
    return;
  }
  mojo::MakeSelfOwnedReceiver(
      base::WrapUnique(new CrossOriginStorageManagerImpl(browser_context,
                                                         origin, frame_id)),
      std::move(receiver));
}

CrossOriginStorageManagerImpl::CrossOriginStorageManagerImpl(
    BrowserContext* browser_context,
    const url::Origin& origin,
    GlobalRenderFrameHostId frame_id)
    : browser_context_(browser_context),
      origin_(origin),
      frame_id_(frame_id) {}

CrossOriginStorageManagerImpl::~CrossOriginStorageManagerImpl() = default;

bool CrossOriginStorageManagerImpl::IsAllowedByPermissionsPolicy() const {
  if (!frame_id_) {
    // A worker's permissions policy is inherited from its owner and is
    // evaluated in the renderer, where it is available. There is no frame here
    // to consult, so this check does not apply.
    return true;
  }
  RenderFrameHost* frame = RenderFrameHost::FromID(frame_id_);
  if (!frame) {
    return false;
  }
  return frame->IsFeatureEnabled(
      network::mojom::PermissionsPolicyFeature::kCrossOriginStorage);
}

void CrossOriginStorageManagerImpl::RequestFileHandle(
    blink::mojom::CrossOriginStorageHashPtr hash,
    bool create,
    blink::mojom::CrossOriginStorageScope scope,
    const std::vector<url::Origin>& origins,
    RequestFileHandleCallback callback) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

  if (!IsAllowedByPermissionsPolicy()) {
    std::move(callback).Run(
        blink::mojom::FileSystemAccessError::New(
            blink::mojom::FileSystemAccessStatus::kPermissionDenied,
            base::File::FILE_OK,
            "Cross-Origin Storage is disabled by Permissions Policy in this "
            "context."),
        mojo::NullRemote());
    return;
  }

  CrossOriginStorageRegistry* registry =
      CrossOriginStorageRegistry::GetOrCreateForBrowserContext(
          browser_context_);
  if (!registry) {
    std::move(callback).Run(
        blink::mojom::FileSystemAccessError::New(
            blink::mojom::FileSystemAccessStatus::kInvalidState,
            base::File::FILE_OK, "Cross-Origin Storage is unavailable."),
        mojo::NullRemote());
    return;
  }

  registry->RequestFileHandle(origin_, hash->algorithm, hash->value, create,
                              ToScope(scope), origins, std::move(callback));
}

}  // namespace content
