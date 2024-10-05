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

class Jitter_RNG_Tests final : public Test {
      Test::Result test_basic_rng() {
         const int max_sample_count = 512;
         std::vector<uint8_t> buf(max_sample_count);
         Botan::Jitter_RNG rng{};

         for(size_t sample_count = 0; sample_count <= max_sample_count; ++sample_count) {
            rng.randomize(buf.data(), sample_count);
         }

         Test::Result result{"JitterRNG basic usage"};
         result.test_success();
         return result;
      }

      Test::Result test_entropy_source() {
         Botan::Entropy_Sources entropy_sources;
         entropy_sources.add_source(Botan::Entropy_Source::create("jitter_rng"));
         Botan::AutoSeeded_RNG rng{entropy_sources};
         std::vector<uint8_t> buf(512);
         rng.randomize(buf.data(), buf.size());

         Test::Result result{"JitterRNG as entropy source"};
         result.test_success();
         return result;
      }

      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_basic_rng());
         results.push_back(test_entropy_source());
         return results;
      }
};

BOTAN_REGISTER_TEST("rng", "jitter_rng_unit", Jitter_RNG_Tests);

}  // namespace Botan_Tests

#endif
