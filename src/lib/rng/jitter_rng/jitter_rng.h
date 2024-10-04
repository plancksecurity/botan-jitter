/*
* CPU Jitter Random Number Generator
* (C) 2024 Planck Security S.A.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_JITTER_RNG_H_
#define BOTAN_JITTER_RNG_H_

#include <botan/rng.h>

namespace Botan {

/*
* RNG using libjitterentropy (https://github.com/smuellerDD/jitterentropy-library).
*/
class BOTAN_PUBLIC_API(3, 6) Jitter_RNG final : public RandomNumberGenerator {
   public:
      Jitter_RNG();
      ~Jitter_RNG();

      std::string name() const override { return "JitterRNG"; }

      bool is_seeded() const override { return true; }

      bool accepts_input() const override { return false; }

      void clear() override {}

      void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) override;

   private:
      struct Rand_Data;
      std::unique_ptr<Rand_Data> m_jitter;
};
}  // namespace Botan

#endif
