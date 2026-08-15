# Cross-Origin Storage (COS) — Chromium implementation

A backup of an in-progress Chromium implementation of the
[Cross-Origin Storage API](https://wicg.github.io/cross-origin-storage/).

Chromium is not developed on GitHub. Changes are reviewed as CLs on
[Gerrit](https://chromium-review.googlesource.com/), not as pull requests, and
the Chromium repository's history is ~65 GB — far too large to mirror here. So
this repository holds the change itself rather than a fork of the tree.

## What is here

    cl/cross-origin-storage.patch   The complete change as a git patch (12.5 MB;
                                    most of it is the Public Hash List binary,
                                    base85-encoded).
    cl/cos-chromium.bundle          The same commit as a git bundle (9.6 MB),
                                    which restores with full commit metadata.
    tree/                           The new files at their real in-tree paths,
                                    so they can be read on GitHub without
                                    applying anything. Modified existing files
                                    are only in the patch and bundle.

## Restoring it into a Chromium checkout

From the root of a `chromium/src` checkout:

    # Option A: the bundle, which keeps the original commit and its message.
    git fetch /path/to/cos-chromium.bundle
    git checkout -b cross-origin-storage FETCH_HEAD

    # Option B: the patch.
    git checkout -b cross-origin-storage origin/main
    git am /path/to/cross-origin-storage.patch

Both are based on Chromium `origin/main` at the commit recorded in the patch
header. On a much newer tree, expect to rebase.

To upload it for review, the Chromium equivalent of opening a pull request is:

    git cl upload

## State of the work

Working, with the imperative `navigator.crossOriginStorage` API implemented and
passing its Web Platform Tests. What is *not* done is written up in the commit
message and in `third_party/cross_origin_storage_public_hash_list/README.chromium`.

Known outstanding items at the time of this backup:

* The `webexposed` interface-listing baselines need regenerating, because the
  feature is enabled by default in this branch and therefore appears in the
  listings.
* No tracking bug is filed; the commit says `Bug: none yet`.
* `third_party/cross_origin_storage_public_hash_list/` adds a ~9.5 MB binary and
  will need OWNERS and security review before it could land.
* Nothing schedules a refresh of the Public Hash List. The scripting for it
  exists (`generate_public_hash_list.py --check`), but the scheduled job does
  not.

The declarative HTML, CSS and JavaScript import-attribute integrations are not
implemented — they are defined in their own host-language specifications.
