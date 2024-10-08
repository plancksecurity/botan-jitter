/*
* (C) 2024 Planck Security S.A.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <vector>

#include <botan/build.h>

#ifdef BOTAN_HAS_JITTER_RNG

   #include <botan/auto_rng.h>
   #include <botan/entropy_src.h>
   #include <botan/jitter_rng.h>
   #include <botan/system_rng.h>

   #include "tests.h"

namespace Botan_Tests {

std::vector<Test::Result> test_jitter_rng() {
   return {
      CHECK("Jitter_RNG basic usage",
            [](Test::Result&) {
               constexpr size_t max_sample_count = 512;

               Botan::Jitter_RNG rng;
               for(size_t sample_count = 0; sample_count <= max_sample_count; ++sample_count) {
                  [[maybe_unused]] auto buf = rng.random_vec(sample_count);
               }
            }),

      CHECK("JitterRNG as entropy source",
            [](Test::Result&) {
               Botan::Entropy_Sources entropy_sources;
               entropy_sources.add_source(Botan::Entropy_Source::create("jitter_rng"));
               Botan::AutoSeeded_RNG rng{entropy_sources};

               [[maybe_unused]] auto buf = rng.random_vec(512);
            }),
   };
}

BOTAN_REGISTER_TEST_FN("rng", "jitter_rng", test_jitter_rng);

}  // namespace Botan_Tests

#endif
