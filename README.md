# Chromium with Cross-Origin Storage (COS)

A prebuilt Chromium with the
[Cross-Origin Storage API](https://wicg.github.io/cross-origin-storage/)
**enabled by default**, so the API can be tried without building Chromium or
setting any flags.

**[→ Download the latest build](../../releases/latest)** (Linux x86_64)

The API is **off by default**. After downloading, enable it in
`about://flags` ("Cross-Origin Storage") and restart, or launch with
`./chrome --enable-features=CrossOriginStorage`. Without that,
`navigator.crossOriginStorage` is `undefined`.

## The code

The implementation is not hosted here. Chromium is reviewed on Gerrit rather
than GitHub, so the change lives there:

**[crbug.com CL 8256403 — Implement the Cross-Origin Storage (COS) API](https://chromium-review.googlesource.com/c/chromium/src/+/8256403)**

It is marked *Work in Progress*: the diff is public and readable, but it is not
ready for review yet. Comments belong on the CL.

## Trying it

```
tar -xzf chromium-cos-linux-x64.tar.gz
cd chromium-cos
./chrome --enable-features=CrossOriginStorage
```

`navigator.crossOriginStorage` is a secure-context API, so test over
`https://` or on `http://localhost` / `http://127.0.0.1`.

From DevTools on any `https://` page:

```js
const bytes = new TextEncoder().encode('hello cos');
const d = await crypto.subtle.digest('SHA-256', bytes);
const value = [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
const hash = {algorithm: 'SHA-256', value};

const h = await navigator.crossOriginStorage.getFileHandle(hash, {create: true});
const w = await h.createWritable();
await w.write(new Blob([bytes]));
await w.close();

const f = await (await navigator.crossOriginStorage.getFileHandle(hash)).getFile();
console.log(await f.text());   // "hello cos"
```

`cross_origin_storage_public_hash_list.bin` must stay beside the `chrome`
binary. It is the Public Hash List, the allowlist that decides whether a
`'*'`-scoped entry may be disclosed to an origin that did not store it. Without
it the browser still runs, but nothing is ever shared across origins, because
the gate fails closed.

## What works

Implemented: the imperative `navigator.crossOriginStorage` API — the three
disclosure scopes (same-site, an explicit origins list, and `'*'`), Public Hash
List availability gating, GREASE'ing, visibility upgrades, per-origin quota and
eviction, rate limiting, and Permissions Policy integration. Handles are
transferable with `postMessage()` to a same-origin worker or frame, carrying
their readability with them. Available in windows, dedicated workers, shared
workers and service workers.

Not implemented, because each is defined in its own host-language
specification: the declarative HTML `crossoriginstorage` attribute, the CSS
`cross-origin-storage()` modifier, and the JavaScript `crossOriginStorage`
import attribute.

## Please read this before running it

These builds are **unofficial developer builds**, not Google Chrome. They are
unsigned, never auto-update, receive no security fixes, and are built from a
development branch rather than from Chromium trunk. The API they exist to
demonstrate is an unshipped proposal whose implementation has not had a
security review. Use them to try this API, and not as a browser.

## Licensing

Chromium is BSD-3-Clause plus a large number of third-party licenses; see
[the Chromium source](https://chromium.googlesource.com/chromium/src/+/main/LICENSE)
and `chrome://credits` in the build itself. The bundled
`cross_origin_storage_public_hash_list.bin` is derived from the
[WICG Public Hash List](https://github.com/WICG/cross-origin-storage/tree/main/public-hash-list),
which is Apache-2.0.

## Links

* [Spec](https://wicg.github.io/cross-origin-storage/)
* [Explainer](https://github.com/WICG/cross-origin-storage)
* [Web Platform Tests](https://github.com/web-platform-tests/wpt/pull/61811)
