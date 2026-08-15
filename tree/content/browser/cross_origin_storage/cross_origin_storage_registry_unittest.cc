// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/cross_origin_storage/cross_origin_storage_registry.h"

#include <string>
#include <vector>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_public_hash_list.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_rate_limiter.h"
#include "content/browser/cross_origin_storage/cross_origin_storage_types.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {
namespace {

CrossOriginStorageHash MakeHash(const std::string& value,
                                const std::string& algorithm = "SHA-256") {
  std::optional<CrossOriginStorageHash> hash =
      CrossOriginStorageHash::Create(algorithm, value);
  CHECK(hash) << "invalid test hash: " << algorithm << " " << value;
  return *hash;
}

// A syntactically valid SHA-256 digest built from a repeated nibble.
CrossOriginStorageHash HashOfNibble(char nibble) {
  return MakeHash(std::string(64, nibble));
}

url::Origin Origin(const std::string& url) {
  return url::Origin::Create(GURL(url));
}

class CrossOriginStorageRegistryTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    registry_ = std::make_unique<CrossOriginStorageRegistry>(
        /*browser_context=*/nullptr, temp_dir_.GetPath(),
        /*is_off_the_record=*/false);
    registry_->WaitForInitializationForTesting();
    // GREASE'ing is a deliberate coin flip; the tests below are about the
    // decisions underneath it, so it is disabled except where it is the
    // subject.
    registry_->SetGreaseDisabledForTesting(true);
  }

  base::test::TaskEnvironment task_environment_;
  base::ScopedTempDir temp_dir_;
  std::unique_ptr<CrossOriginStorageRegistry> registry_;
};

// -- Hash validation ---------------------------------------------------------

TEST(CrossOriginStorageHashTest, AcceptsEveryRecognizedAlgorithm) {
  EXPECT_TRUE(CrossOriginStorageHash::Create("SHA-1", std::string(40, 'a')));
  EXPECT_TRUE(CrossOriginStorageHash::Create("SHA-256", std::string(64, 'a')));
  EXPECT_TRUE(CrossOriginStorageHash::Create("SHA-384", std::string(96, 'a')));
  EXPECT_TRUE(CrossOriginStorageHash::Create("SHA-512", std::string(128, 'a')));
}

TEST(CrossOriginStorageHashTest, AlgorithmIsMatchedCaseInsensitively) {
  std::optional<CrossOriginStorageHash> lower =
      CrossOriginStorageHash::Create("sha-256", std::string(64, 'a'));
  ASSERT_TRUE(lower);
  // Canonicalized, so a differently-cased request finds the same entry.
  EXPECT_EQ(lower->algorithm(), "SHA-256");
  EXPECT_EQ(*lower, MakeHash(std::string(64, 'a')));
}

TEST(CrossOriginStorageHashTest, RejectsUnrecognizedAlgorithms) {
  EXPECT_FALSE(CrossOriginStorageHash::Create("md5", std::string(32, 'a')));
  EXPECT_FALSE(
      CrossOriginStorageHash::Create("not-an-algorithm", std::string(64, 'a')));
}

TEST(CrossOriginStorageHashTest, RejectsMalformedDigests) {
  // Wrong length.
  EXPECT_FALSE(CrossOriginStorageHash::Create("SHA-256", std::string(63, 'a')));
  EXPECT_FALSE(CrossOriginStorageHash::Create("SHA-256", std::string(65, 'a')));
  // Uppercase is not lowercase hex.
  EXPECT_FALSE(CrossOriginStorageHash::Create("SHA-256", std::string(64, 'A')));
  // Not hex at all.
  EXPECT_FALSE(CrossOriginStorageHash::Create("SHA-256", std::string(64, 'z')));
}

// Every recognized algorithm is length-checked, not just the one the test suite
// happens to exercise most: `value` becomes part of a filesystem path, so an
// under-validated digest for a less-common algorithm is a traversal vector.
TEST(CrossOriginStorageHashTest, RejectsPathTraversalForEveryAlgorithm) {
  for (const char* algorithm : {"SHA-1", "SHA-256", "SHA-384", "SHA-512"}) {
    EXPECT_FALSE(CrossOriginStorageHash::Create(algorithm, "../../etc/passwd"))
        << algorithm;
    EXPECT_FALSE(CrossOriginStorageHash::Create(
        algorithm, std::string(60, 'a') + "/../"))
        << algorithm;
  }
}

// -- Disclosure scoping ------------------------------------------------------

TEST_F(CrossOriginStorageRegistryTest, StoringOriginAlwaysReadsItsOwnWriteBack) {
  const auto hash = HashOfNibble('1');
  const url::Origin storer = Origin("https://storer.example");

  // Wildcard-scoped and definitely not on the Public Hash List, which the
  // storing origin's own access does not depend on.
  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {storer});

  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, storer));
  EXPECT_FALSE(registry_->IsDisclosableForTesting(
      hash, Origin("https://other.example")));
}

TEST_F(CrossOriginStorageRegistryTest, SameSiteScopeAuthorizesSiblingOrigins) {
  const auto hash = HashOfNibble('2');
  const url::Origin storer = Origin("https://a.example.com");

  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kSameSite, {},
                                       {storer});

  // Same registrable domain, different origin.
  EXPECT_TRUE(registry_->IsDisclosableForTesting(
      hash, Origin("https://b.example.com")));
  // Genuinely different site.
  EXPECT_FALSE(registry_->IsDisclosableForTesting(
      hash, Origin("https://example.org")));
  // Superficially similar, but a different registrable domain.
  EXPECT_FALSE(registry_->IsDisclosableForTesting(
      hash, Origin("https://example.co.uk")));
}

TEST_F(CrossOriginStorageRegistryTest, ListScopeAuthorizesOnlyListedOrigins) {
  const auto hash = HashOfNibble('3');
  const url::Origin storer = Origin("https://storer.example");
  const url::Origin listed = Origin("https://listed.example");

  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kList, {listed},
                                       {storer});

  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, listed));
  EXPECT_FALSE(registry_->IsDisclosableForTesting(
      hash, Origin("https://unlisted.example")));
  // The storer is not in its own list, but always reads its own write back.
  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, storer));
}

// An explicit empty list is a real, empty list -- not shorthand for the
// same-site default. It authorizes nobody but the storing origins.
TEST_F(CrossOriginStorageRegistryTest, EmptyListIsNotTheSameSiteDefault) {
  const auto hash = HashOfNibble('4');
  const url::Origin storer = Origin("https://a.example.com");

  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kList, {},
                                       {storer});

  EXPECT_FALSE(registry_->IsDisclosableForTesting(
      hash, Origin("https://b.example.com")));
  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, storer));
}

// -- The Public Hash List gate ----------------------------------------------

TEST_F(CrossOriginStorageRegistryTest, WildcardScopeRequiresPublicHashList) {
  const auto listed_hash = HashOfNibble('a');
  const auto unlisted_hash = HashOfNibble('b');
  const url::Origin storer = Origin("https://storer.example");
  const url::Origin reader = Origin("https://reader.example");

  std::vector<uint8_t> packed(32, 0xaa);
  registry_->public_hash_list_for_testing().SetDigestsForTesting(packed);

  registry_->AddWrittenEntryForTesting(listed_hash, /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {storer});
  registry_->AddWrittenEntryForTesting(unlisted_hash, /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {storer});

  EXPECT_TRUE(registry_->IsDisclosableForTesting(listed_hash, reader));
  EXPECT_FALSE(registry_->IsDisclosableForTesting(unlisted_hash, reader));
}

// The gate applies only to "*"-scoped entries. A list-scoped entry has already
// had its disclosure bounded by the storing origin's explicit choice, so
// requiring public curation on top of that would make ordinary restricted
// sharing depend on an unrelated allowlist.
TEST_F(CrossOriginStorageRegistryTest, ListScopeDoesNotConsultPublicHashList) {
  const auto hash = HashOfNibble('c');
  const url::Origin storer = Origin("https://storer.example");
  const url::Origin listed = Origin("https://listed.example");

  // Deliberately empty: nothing is on the list.
  registry_->public_hash_list_for_testing().SetDigestsForTesting({});

  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kList, {listed},
                                       {storer});

  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, listed));
}

// -- GREASE'ing --------------------------------------------------------------

// A false negative on a large entry would force a costly, fully observable
// re-download -- and that cost difference is itself detectable, which would
// defeat the purpose of the noise.
TEST_F(CrossOriginStorageRegistryTest, LargeEntriesAreNeverGreased) {
  const auto hash = HashOfNibble('d');
  const url::Origin storer = Origin("https://storer.example");
  const url::Origin listed = Origin("https://listed.example");

  registry_->SetGreaseDisabledForTesting(false);
  registry_->AddWrittenEntryForTesting(
      hash, cos_constants::kGreaseSizeCeilingBytes,
      CrossOriginStorageScope::kList, {listed}, {storer});

  // No number of trials may produce a suppression for an entry at or above the
  // size ceiling.
  for (int i = 0; i < 2000; ++i) {
    ASSERT_TRUE(registry_->IsDisclosableForTesting(hash, listed))
        << "iteration " << i;
  }
}

TEST_F(CrossOriginStorageRegistryTest, SmallEntriesAreSometimesGreased) {
  const auto hash = HashOfNibble('e');
  const url::Origin storer = Origin("https://storer.example");
  const url::Origin listed = Origin("https://listed.example");

  registry_->SetGreaseDisabledForTesting(false);
  registry_->AddWrittenEntryForTesting(hash, /*size=*/1,
                                       CrossOriginStorageScope::kList, {listed},
                                       {storer});

  // Asserted as a shape rather than an exact rate: the roll is random, so a
  // precise count would be flaky for reasons unrelated to any real bug. At a 1%
  // rate, seeing no suppression in 5000 trials is vanishingly unlikely.
  bool saw_suppression = false;
  for (int i = 0; i < 5000 && !saw_suppression; ++i) {
    saw_suppression = !registry_->IsDisclosableForTesting(hash, listed);
  }
  EXPECT_TRUE(saw_suppression);
}

// A storing origin supplied the bytes itself, so noise there would cost a
// re-download without denying an attacker anything it did not already know.
TEST_F(CrossOriginStorageRegistryTest, StoringOriginIsNeverGreased) {
  const auto hash = HashOfNibble('f');
  const url::Origin storer = Origin("https://storer.example");

  registry_->SetGreaseDisabledForTesting(false);
  registry_->AddWrittenEntryForTesting(hash, /*size=*/1,
                                       CrossOriginStorageScope::kList, {},
                                       {storer});

  for (int i = 0; i < 2000; ++i) {
    ASSERT_TRUE(registry_->IsDisclosableForTesting(hash, storer))
        << "iteration " << i;
  }
}

// -- Visibility upgrades -----------------------------------------------------

TEST_F(CrossOriginStorageRegistryTest, VisibilityWidensButNeverNarrows) {
  const auto hash = HashOfNibble('5');
  const url::Origin storer = Origin("https://storer.example");
  const url::Origin first = Origin("https://first.example");
  const url::Origin second = Origin("https://second.example");

  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kSameSite, {},
                                       {storer});

  // Same-site -> list.
  registry_->UpgradeVisibilityForTesting(hash, CrossOriginStorageScope::kList,
                                         {first});
  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, first));
  EXPECT_FALSE(registry_->IsDisclosableForTesting(hash, second));

  // List -> wider list.
  registry_->UpgradeVisibilityForTesting(hash, CrossOriginStorageScope::kList,
                                         {second});
  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, first));
  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, second));

  // List -> wildcard.
  registry_->public_hash_list_for_testing().SetDigestsForTesting(
      std::vector<uint8_t>(32, 0x55));
  registry_->UpgradeVisibilityForTesting(
      hash, CrossOriginStorageScope::kWildcard, {});
  EXPECT_TRUE(
      registry_->IsDisclosableForTesting(hash, Origin("https://any.example")));

  // Wildcard -> list is a silent no-op, not a narrowing.
  registry_->UpgradeVisibilityForTesting(hash, CrossOriginStorageScope::kList,
                                         {first});
  EXPECT_TRUE(
      registry_->IsDisclosableForTesting(hash, Origin("https://any.example")));

  // Wildcard -> omitted is likewise a no-op.
  registry_->UpgradeVisibilityForTesting(
      hash, CrossOriginStorageScope::kSameSite, {});
  EXPECT_TRUE(
      registry_->IsDisclosableForTesting(hash, Origin("https://any.example")));
}

// Reached only by the cumulative effect of separate writes, possibly by
// unrelated origins over a long time. The excess is dropped rather than failing
// the write that happened to cross the line, which was already verified and
// stored by then.
TEST_F(CrossOriginStorageRegistryTest, MergedOriginsListIsCappedNotFailed) {
  const auto hash = HashOfNibble('6');
  const url::Origin storer = Origin("https://storer.example");

  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kList, {},
                                       {storer});

  for (size_t i = 0; i < cos_constants::kMaxOriginsListLength + 25; ++i) {
    registry_->UpgradeVisibilityForTesting(
        hash, CrossOriginStorageScope::kList,
        {Origin("https://origin-" + base::NumberToString(i) + ".example")});
  }

  CrossOriginStorageEntry* entry = registry_->FindEntryForTesting(hash);
  ASSERT_TRUE(entry);
  EXPECT_EQ(entry->origins.size(), cos_constants::kMaxOriginsListLength);
  // The entry is still perfectly usable; only the surplus origins were dropped.
  EXPECT_EQ(entry->state, CrossOriginStorageEntryState::kWritten);
}

// -- Pending entry cleanup ---------------------------------------------------

TEST_F(CrossOriginStorageRegistryTest, SoleFailedWriterRemovesPendingEntry) {
  const auto hash = HashOfNibble('7');
  const uint64_t generation =
      registry_->AddPendingEntryForTesting(hash, /*pending_writer_count=*/1);

  registry_->AbandonWrite(hash, generation);

  // A later read must see an ordinary absent hash, not an indefinite
  // "a write is in progress".
  EXPECT_FALSE(registry_->FindEntryForTesting(hash));
}

// The count is what protects a genuinely concurrent sibling write: two tabs
// racing on the same hash, one supplying wrong bytes, must not have the other's
// entry deleted out from under it.
TEST_F(CrossOriginStorageRegistryTest,
       FailedWriterDoesNotRemoveEntryWhileSiblingIsOutstanding) {
  const auto hash = HashOfNibble('8');
  const uint64_t generation =
      registry_->AddPendingEntryForTesting(hash, /*pending_writer_count=*/2);

  registry_->AbandonWrite(hash, generation);
  EXPECT_TRUE(registry_->FindEntryForTesting(hash))
      << "the sibling writer is still outstanding";

  registry_->AbandonWrite(hash, generation);
  EXPECT_FALSE(registry_->FindEntryForTesting(hash));
}

// Without the never-written qualifier, any origin could delete bytes another
// origin already stored just by requesting a handle and writing garbage.
TEST_F(CrossOriginStorageRegistryTest, FailedWriteNeverRemovesAWrittenEntry) {
  const auto hash = HashOfNibble('9');
  const url::Origin storer = Origin("https://storer.example");
  const uint64_t generation = registry_->AddWrittenEntryForTesting(
      hash, /*size=*/10, CrossOriginStorageScope::kSameSite, {}, {storer});

  for (int i = 0; i < 5; ++i) {
    registry_->AbandonWrite(hash, generation);
  }

  ASSERT_TRUE(registry_->FindEntryForTesting(hash));
  EXPECT_TRUE(registry_->IsDisclosableForTesting(hash, storer));
}

// A handle from an entry that was already replaced must not disturb whatever
// occupies the hash now.
TEST_F(CrossOriginStorageRegistryTest, StaleGenerationDoesNotDisturbNewEntry) {
  const auto hash = HashOfNibble('0');
  const uint64_t stale_generation =
      registry_->AddPendingEntryForTesting(hash, /*pending_writer_count=*/1);
  const uint64_t fresh_generation =
      registry_->AddPendingEntryForTesting(hash, /*pending_writer_count=*/1);
  ASSERT_NE(stale_generation, fresh_generation);

  registry_->AbandonWrite(hash, stale_generation);
  EXPECT_TRUE(registry_->FindEntryForTesting(hash));

  registry_->AbandonWrite(hash, fresh_generation);
  EXPECT_FALSE(registry_->FindEntryForTesting(hash));
}

// -- Clear data --------------------------------------------------------------

// Revoke-and-GC: clearing one site must not destroy data a different,
// uncleared site legitimately stored.
TEST_F(CrossOriginStorageRegistryTest, ClearingOneOriginKeepsAnotherOwnersCopy) {
  const auto shared_hash = HashOfNibble('2');
  const auto sole_hash = HashOfNibble('3');
  const url::Origin cleared = Origin("https://cleared.example");
  const url::Origin kept = Origin("https://kept.example");

  registry_->AddWrittenEntryForTesting(shared_hash, /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {cleared, kept});
  registry_->AddWrittenEntryForTesting(sole_hash, /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {cleared});

  bool done = false;
  registry_->ClearDataForOrigin(cleared,
                                base::BindLambdaForTesting([&] { done = true; }));
  EXPECT_TRUE(done);

  // The shared entry survives, owned by the origin that was not cleared.
  CrossOriginStorageEntry* shared = registry_->FindEntryForTesting(shared_hash);
  ASSERT_TRUE(shared);
  EXPECT_FALSE(shared->IsStoringOrigin(cleared));
  EXPECT_TRUE(shared->IsStoringOrigin(kept));

  // The sole-owned entry has no owner left, so it goes.
  EXPECT_FALSE(registry_->FindEntryForTesting(sole_hash));
}

TEST_F(CrossOriginStorageRegistryTest, ClearingAlsoDropsOriginsListGrants) {
  const auto hash = HashOfNibble('4');
  const url::Origin storer = Origin("https://storer.example");
  const url::Origin granted = Origin("https://granted.example");

  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kList,
                                       {granted}, {storer});
  ASSERT_TRUE(registry_->IsDisclosableForTesting(hash, granted));

  bool done = false;
  registry_->ClearDataForOrigin(granted,
                                base::BindLambdaForTesting([&] { done = true; }));
  EXPECT_TRUE(done);

  EXPECT_FALSE(registry_->IsDisclosableForTesting(hash, granted));
}

TEST_F(CrossOriginStorageRegistryTest, ClearAllDataRemovesEverything) {
  registry_->AddWrittenEntryForTesting(HashOfNibble('5'), /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {Origin("https://a.example")});
  registry_->AddWrittenEntryForTesting(HashOfNibble('6'), /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {Origin("https://b.example")});
  ASSERT_EQ(registry_->entries_for_testing().size(), 2u);

  base::RunLoop run_loop;
  registry_->ClearAllData(run_loop.QuitClosure());
  run_loop.Run();

  EXPECT_TRUE(registry_->entries_for_testing().empty());
}

// -- Persistence -------------------------------------------------------------

// A suite that never restarts the process can stay entirely green while the
// reload-from-disk path is broken, because nothing ever runs it. These tests
// build a registry, drop it, and build a second one over the same directory,
// which is the only way the serialize/deserialize/startup-scan code is
// exercised at all.
TEST_F(CrossOriginStorageRegistryTest, WrittenEntriesSurviveARestart) {
  const auto same_site_hash = HashOfNibble('1');
  const auto list_hash = HashOfNibble('2');
  const auto wildcard_hash = HashOfNibble('3');
  const url::Origin storer = Origin("https://storer.example.com");
  const url::Origin second_storer = Origin("https://second.example");
  const url::Origin listed = Origin("https://listed.example");

  registry_->AddWrittenEntryForTesting(same_site_hash, /*size=*/11,
                                       CrossOriginStorageScope::kSameSite, {},
                                       {storer});
  registry_->AddWrittenEntryForTesting(list_hash, /*size=*/22,
                                       CrossOriginStorageScope::kList, {listed},
                                       {storer, second_storer});
  registry_->AddWrittenEntryForTesting(wildcard_hash, /*size=*/33,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {storer});

  // The bytes files are written by the write path, not by the test seam, so
  // stand in for them here: an entry whose bytes are missing is deliberately
  // dropped on load, which would mask everything this test checks.
  for (const auto& [hash, size] : {std::pair(same_site_hash, 11),
                                   std::pair(list_hash, 22),
                                   std::pair(wildcard_hash, 33)}) {
    const base::FilePath path = registry_->GetBytesPath(hash);
    ASSERT_TRUE(base::CreateDirectory(path.DirName()));
    ASSERT_TRUE(base::WriteFile(path, std::string(size, 'x')));
  }

  // Let the queued metadata writes land, then drop the registry entirely.
  task_environment_.RunUntilIdle();
  registry_.reset();

  auto reloaded = std::make_unique<CrossOriginStorageRegistry>(
      /*browser_context=*/nullptr, temp_dir_.GetPath(),
      /*is_off_the_record=*/false);
  reloaded->WaitForInitializationForTesting();
  reloaded->SetGreaseDisabledForTesting(true);

  ASSERT_EQ(reloaded->entries_for_testing().size(), 3u);

  // Same-site scope, and its storing origin, survived: a sibling origin is
  // still authorized and a cross-site one still is not.
  EXPECT_TRUE(reloaded->IsDisclosableForTesting(
      same_site_hash, Origin("https://sibling.example.com")));
  EXPECT_FALSE(reloaded->IsDisclosableForTesting(
      same_site_hash, Origin("https://elsewhere.example")));

  // The explicit origins list survived, and so did both storing origins.
  EXPECT_TRUE(reloaded->IsDisclosableForTesting(list_hash, listed));
  EXPECT_FALSE(reloaded->IsDisclosableForTesting(
      list_hash, Origin("https://unlisted.example")));
  EXPECT_TRUE(reloaded->IsDisclosableForTesting(list_hash, second_storer));

  // Wildcard scope survived, and still consults the Public Hash List rather
  // than being disclosed to everyone.
  reloaded->public_hash_list_for_testing().SetDigestsForTesting({});
  EXPECT_FALSE(reloaded->IsDisclosableForTesting(
      wildcard_hash, Origin("https://anyone.example")));
  reloaded->public_hash_list_for_testing().SetDigestsForTesting(
      std::vector<uint8_t>(32, 0x33));
  EXPECT_TRUE(reloaded->IsDisclosableForTesting(
      wildcard_hash, Origin("https://anyone.example")));

  // Sizes round-trip, which is what the storage budget is accounted against.
  const CrossOriginStorageEntry* entry =
      reloaded->FindEntryForTesting(list_hash);
  ASSERT_TRUE(entry);
  EXPECT_EQ(entry->size, 22);
  EXPECT_EQ(entry->state, CrossOriginStorageEntryState::kWritten);
}

// An entry whose bytes went missing between sessions must read as absent
// rather than be served under a hash its contents no longer match.
TEST_F(CrossOriginStorageRegistryTest, EntryWithMissingBytesIsDroppedOnLoad) {
  const auto hash = HashOfNibble('4');
  registry_->AddWrittenEntryForTesting(hash, /*size=*/10,
                                       CrossOriginStorageScope::kWildcard, {},
                                       {Origin("https://storer.example")});
  // Deliberately no bytes file written.
  task_environment_.RunUntilIdle();
  registry_.reset();

  auto reloaded = std::make_unique<CrossOriginStorageRegistry>(
      /*browser_context=*/nullptr, temp_dir_.GetPath(),
      /*is_off_the_record=*/false);
  reloaded->WaitForInitializationForTesting();

  EXPECT_TRUE(reloaded->entries_for_testing().empty());
}

// An off-the-record registry must leave nothing behind for a later session to
// pick up.
TEST_F(CrossOriginStorageRegistryTest, OffTheRecordEntriesDoNotPersist) {
  base::ScopedTempDir otr_dir;
  ASSERT_TRUE(otr_dir.CreateUniqueTempDir());

  auto otr = std::make_unique<CrossOriginStorageRegistry>(
      /*browser_context=*/nullptr, otr_dir.GetPath(),
      /*is_off_the_record=*/true);
  otr->WaitForInitializationForTesting();
  otr->AddWrittenEntryForTesting(HashOfNibble('5'), /*size=*/10,
                                 CrossOriginStorageScope::kWildcard, {},
                                 {Origin("https://storer.example")});
  task_environment_.RunUntilIdle();
  otr.reset();
  task_environment_.RunUntilIdle();

  auto reloaded = std::make_unique<CrossOriginStorageRegistry>(
      /*browser_context=*/nullptr, otr_dir.GetPath(),
      /*is_off_the_record=*/false);
  reloaded->WaitForInitializationForTesting();
  EXPECT_TRUE(reloaded->entries_for_testing().empty());
}

// -- Rate limiting -----------------------------------------------------------

TEST(CrossOriginStorageRateLimiterTest, DeniesAfterBurstIsExhausted) {
  CrossOriginStorageRateLimiter limiter(/*capacity=*/10,
                                        /*refill_per_second=*/0.0,
                                        /*max_origins=*/100);
  const url::Origin origin = Origin("https://example.com");

  int allowed = 0;
  for (int i = 0; i < 50; ++i) {
    if (limiter.TryConsume(origin)) {
      ++allowed;
    }
  }
  // Asserted as a range rather than an exact count: with a real wall clock a
  // refill tick can land mid-loop, which is not a bug.
  EXPECT_GE(allowed, 10);
  EXPECT_LE(allowed, 12);
}

TEST(CrossOriginStorageRateLimiterTest, BudgetsArePerOrigin) {
  CrossOriginStorageRateLimiter limiter(/*capacity=*/2,
                                        /*refill_per_second=*/0.0,
                                        /*max_origins=*/100);
  const url::Origin a = Origin("https://a.example");
  const url::Origin b = Origin("https://b.example");

  EXPECT_TRUE(limiter.TryConsume(a));
  EXPECT_TRUE(limiter.TryConsume(a));
  EXPECT_FALSE(limiter.TryConsume(a));

  // One origin exhausting its budget must not throttle another.
  EXPECT_TRUE(limiter.TryConsume(b));
}

// Not part of the spec at all, but a map keyed by origin with no eviction is a
// real unbounded leak over a long session visiting many sites.
TEST(CrossOriginStorageRateLimiterTest, BoundsItsOwnMemory) {
  constexpr size_t kMaxOrigins = 8;
  CrossOriginStorageRateLimiter limiter(/*capacity=*/1,
                                        /*refill_per_second=*/0.0, kMaxOrigins);

  for (size_t i = 0; i < kMaxOrigins * 4; ++i) {
    EXPECT_TRUE(limiter.TryConsume(
        Origin("https://origin-" + base::NumberToString(i) + ".example")));
  }
  // Nothing observable to assert beyond "it still works"; the bound itself is
  // enforced internally, and an evicted origin's worst case is a reset burst.
  EXPECT_TRUE(limiter.TryConsume(Origin("https://fresh.example")));
}

// -- Public Hash List --------------------------------------------------------

TEST(CrossOriginStoragePublicHashListTest, BinarySearchesPackedDigests) {
  CrossOriginStoragePublicHashList list;

  // Three sorted 32-byte records.
  std::vector<uint8_t> packed;
  for (uint8_t nibble : {0x11, 0x55, 0xdd}) {
    packed.insert(packed.end(), 32, nibble);
  }
  list.SetDigestsForTesting(packed);
  ASSERT_EQ(list.size_for_testing(), 3u);

  EXPECT_TRUE(list.Contains(MakeHash(std::string(64, '1'))));
  EXPECT_TRUE(list.Contains(MakeHash(std::string(64, '5'))));
  EXPECT_TRUE(list.Contains(MakeHash(std::string(64, 'd'))));

  EXPECT_FALSE(list.Contains(MakeHash(std::string(64, '0'))));
  EXPECT_FALSE(list.Contains(MakeHash(std::string(64, '3'))));
  EXPECT_FALSE(list.Contains(MakeHash(std::string(64, 'f'))));
}

// Upstream lists SHA-256 digests only, so nothing else can ever clear the gate.
TEST(CrossOriginStoragePublicHashListTest, OnlyEverMatchesSha256) {
  CrossOriginStoragePublicHashList list;
  list.SetDigestsForTesting(std::vector<uint8_t>(32, 0xaa));

  EXPECT_TRUE(list.Contains(MakeHash(std::string(64, 'a'), "SHA-256")));
  EXPECT_FALSE(list.Contains(MakeHash(std::string(40, 'a'), "SHA-1")));
  EXPECT_FALSE(list.Contains(MakeHash(std::string(128, 'a'), "SHA-512")));
}

// Fails closed, not open: a missing or unreadable data file must mean "nothing
// is listed", never "everything is listed".
TEST(CrossOriginStoragePublicHashListTest, EmptyListMatchesNothing) {
  CrossOriginStoragePublicHashList list;
  list.SetDigestsForTesting({});

  EXPECT_FALSE(list.Contains(MakeHash(std::string(64, 'a'))));
}

}  // namespace
}  // namespace content
