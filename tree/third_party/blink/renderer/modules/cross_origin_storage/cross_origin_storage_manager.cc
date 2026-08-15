// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/cross_origin_storage/cross_origin_storage_manager.h"

#include <utility>

#include "services/network/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_stringsequence.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_cross_origin_storage_request_file_handle_hash.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_cross_origin_storage_request_file_handle_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_file_handle.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

// The user agent's "maximum origins list length"
// (https://wicg.github.io/cross-origin-storage/#maximum-origins-list-length).
// Small enough that a list cannot approximate "*", large enough for genuine
// multi-property use. Kept in sync with the browser-side constant, which is
// authoritative; this copy only lets an obviously-too-long list be rejected
// without a round trip.
constexpr wtf_size_t kMaxOriginsListLength = 100;

// The expected hex digest length of every hash algorithm recognized by the Web
// Crypto API. Returns 0 for an unrecognized algorithm.
//
// The spec only normatively constrains "SHA-256"'s length, but validating every
// recognized algorithm matters: the browser derives filesystem paths from
// `value`, so an under-validated digest for a less-common algorithm is a path
// traversal vector. The browser re-validates this independently; this copy is
// what turns a bad request into the spec's TypeError instead of a round trip.
wtf_size_t ExpectedDigestHexLength(const String& algorithm) {
  if (EqualIgnoringAsciiCase(algorithm, "SHA-1")) {
    return 40;
  }
  if (EqualIgnoringAsciiCase(algorithm, "SHA-256")) {
    return 64;
  }
  if (EqualIgnoringAsciiCase(algorithm, "SHA-384")) {
    return 96;
  }
  if (EqualIgnoringAsciiCase(algorithm, "SHA-512")) {
    return 128;
  }
  return 0;
}

bool IsLowercaseHex(const String& value) {
  for (wtf_size_t i = 0; i < value.length(); ++i) {
    const UChar c = value[i];
    const bool is_digit = c >= '0' && c <= '9';
    const bool is_lower_hex_alpha = c >= 'a' && c <= 'f';
    if (!is_digit && !is_lower_hex_alpha) {
      return false;
    }
  }
  return true;
}

}  // namespace

// static
const char CrossOriginStorageManager::kSupplementName[] =
    "CrossOriginStorageManager";

// static
CrossOriginStorageManager* CrossOriginStorageManager::crossOriginStorage(
    NavigatorBase& navigator) {
  auto* supplement =
      Supplement<NavigatorBase>::From<CrossOriginStorageManager>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<CrossOriginStorageManager>(navigator);
    Supplement<NavigatorBase>::ProvideTo(navigator, supplement);
  }
  return supplement;
}

CrossOriginStorageManager::CrossOriginStorageManager(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      remote_(navigator.GetExecutionContext()) {}

ScriptPromise<FileSystemFileHandle>
CrossOriginStorageManager::requestFileHandle(
    ScriptState* script_state,
    const CrossOriginStorageRequestFileHandleHash* hash,
    const CrossOriginStorageRequestFileHandleOptions* options,
    ExceptionState& exception_state) {
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context || context->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The execution context is not valid.");
    return EmptyPromise();
  }

  // Step 5: the Permissions Policy gate runs before any validation, so a
  // policy-blocked context sees NotAllowedError even for a request that would
  // otherwise fail validation.
  // https://wicg.github.io/cross-origin-storage/#requestfilehandle
  if (!context->IsFeatureEnabled(
          network::mojom::PermissionsPolicyFeature::kCrossOriginStorage)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Cross-Origin Storage is disabled by Permissions Policy in this "
        "context.");
    return EmptyPromise();
  }

  // "Validate a COS request".
  // https://wicg.github.io/cross-origin-storage/#validate-a-cos-request
  const wtf_size_t expected_length = ExpectedDigestHexLength(hash->algorithm());
  if (expected_length == 0) {
    exception_state.ThrowTypeError(
        "hash.algorithm is not a hash algorithm name recognized by the Web "
        "Crypto API.");
    return EmptyPromise();
  }
  if (hash->value().length() != expected_length ||
      !IsLowercaseHex(hash->value())) {
    exception_state.ThrowTypeError(
        "hash.value must be a lowercase hexadecimal string of length " +
        String::Number(expected_length) + " for " + hash->algorithm() + ".");
    return EmptyPromise();
  }

  auto scope = mojom::blink::CrossOriginStorageScope::kSameSite;
  Vector<scoped_refptr<const SecurityOrigin>> origins;
  if (options->hasOrigins()) {
    const V8UnionStringOrStringSequence* requested = options->origins();
    if (requested->IsString() && requested->GetAsString() == "*") {
      scope = mojom::blink::CrossOriginStorageScope::kWildcard;
    } else {
      scope = mojom::blink::CrossOriginStorageScope::kList;
      // A single string is treated as a list of one.
      Vector<String> candidates;
      if (requested->IsString()) {
        candidates.push_back(requested->GetAsString());
      } else {
        candidates = requested->GetAsStringSequence();
      }
      if (candidates.size() > kMaxOriginsListLength) {
        exception_state.ThrowTypeError(
            "options.origins exceeds the maximum origins list length of " +
            String::Number(kMaxOriginsListLength) + ".");
        return EmptyPromise();
      }
      origins.reserve(candidates.size());
      for (const String& candidate : candidates) {
        scoped_refptr<const SecurityOrigin> origin =
            SecurityOrigin::CreateFromString(candidate);
        // CreateFromString() yields an opaque origin for a string the URL
        // parser rejects, so this covers both of the spec's failure cases.
        if (!origin || origin->IsOpaque()) {
          exception_state.ThrowTypeError(
              "options.origins contains \"" + candidate +
              "\", which does not parse to a non-opaque origin.");
          return EmptyPromise();
        }
        if (!origins.Contains(origin)) {
          origins.push_back(std::move(origin));
        }
      }
    }
  }

  if (!EnsureRemote(context)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The execution context is not valid.");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemFileHandle>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  auto mojo_hash = mojom::blink::CrossOriginStorageHash::New();
  mojo_hash->algorithm = hash->algorithm();
  mojo_hash->value = hash->value();

  remote_->RequestFileHandle(
      std::move(mojo_hash), options->create(), scope, std::move(origins),
      BindOnce(&CrossOriginStorageManager::OnRequestFileHandleResult,
                    WrapPersistent(this), WrapPersistent(resolver),
                    hash->value()));
  return promise;
}

bool CrossOriginStorageManager::EnsureRemote(ExecutionContext* context) {
  if (remote_.is_bound()) {
    return true;
  }
  context->GetBrowserInterfaceBroker().GetInterface(
      remote_.BindNewPipeAndPassReceiver(
          context->GetTaskRunner(TaskType::kStorage)));
  return remote_.is_bound();
}

void CrossOriginStorageManager::OnRequestFileHandleResult(
    ScriptPromiseResolver<FileSystemFileHandle>* resolver,
    const String& name,
    mojom::blink::FileSystemAccessErrorPtr result,
    mojo::PendingRemote<mojom::blink::FileSystemAccessFileHandle> handle) {
  if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
    file_system_access_error::Reject(resolver, *result);
    return;
  }
  ExecutionContext* context = resolver->GetExecutionContext();
  if (!context || !handle.is_valid()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The execution context is not valid.");
    return;
  }
  // A COS entry has no name of its own; the hash is what identifies it, so
  // that is what the handle reports.
  resolver->Resolve(MakeGarbageCollected<FileSystemFileHandle>(
      context, name, std::move(handle)));
}

void CrossOriginStorageManager::Trace(Visitor* visitor) const {
  visitor->Trace(remote_);
  ScriptWrappable::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
}

}  // namespace blink
