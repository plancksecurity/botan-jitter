/*
* CPU Jitter Random Number Generator
* (C) 2024 Planck Security S.A.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/jitter_rng.h>

#include <jitterentropy.h>

namespace Botan {

class BOTAN_DLL Jitter_RNG::Rand_Data {
   public:
      Rand_Data();
      ~Rand_Data();
      void collect_into_buffer(std::span<uint8_t> buf);

   private:
      rand_data* m_rand_data;
};

Jitter_RNG::Rand_Data::Rand_Data() {
   static int result = jent_entropy_init();

   if(result != 0) {
      // no further details documented regarding the return value
      throw Botan::Internal_Error("JitterRNG: Can not be used");
   }

   const unsigned int oversampling_rate = 0;  // use default oversampling
   const unsigned int flags = 0;

   m_rand_data = jent_entropy_collector_alloc(oversampling_rate, flags);
   if(!m_rand_data) {
      throw Botan::Internal_Error("JitterRNG: Jitter entropy collector could not be allocated");
   }
}

Jitter_RNG::Rand_Data::~Rand_Data() {
   if(m_rand_data) {
      jent_entropy_collector_free(m_rand_data);
   }
}

void Jitter_RNG::Rand_Data::collect_into_buffer(std::span<uint8_t> buf) {
   if(buf.size() == 0) {
      return;
   }

   if(!m_rand_data) {
      throw Botan::Invalid_State("JitterRNG: No jitter entropy collector has been allocated");
   }

   ssize_t num_bytes = jent_read_entropy(m_rand_data, reinterpret_cast<char*>(buf.data()), buf.size());
   if(num_bytes < 0) {
      switch(num_bytes) {
         case -1:  // should never happen because of the check above
            throw Botan::Internal_Error("JitterRNG: Uninitilialized");
         case -2:
            throw Botan::Internal_Error("JitterRNG: SP800-90B repetition count online health test failed");
         case -3:
            throw Botan::Internal_Error("JitterRNG: SP800-90B adaptive proportion online health test failed");
         case -4:
            throw Botan::Internal_Error("JitterRNG: Internal timer generator could not be initialized");
         case -5:
            throw Botan::Internal_Error("JitterRNG: LAG predictor health test failed");
         case -6:
            throw Botan::Internal_Error("JitterRNG: Repetitive count test (RCT) failed permanently");
         case -7:
            throw Botan::Internal_Error("JitterRNG: Adaptive proportion test (APT) failed permanently");
         case -8:
            throw Botan::Internal_Error("JitterRNG: LAG prediction test failed permanently");
         default:
            throw Botan::Internal_Error("JitterRNG: Error reading entropy");
      }
   }
   if(num_bytes < buf.size()) {
      throw Botan::Internal_Error("JitterRNG: Not enough bytes have been produced");
   }
}

Jitter_RNG::Jitter_RNG() : m_jitter{std::make_unique<Rand_Data>()} {}

Jitter_RNG::~Jitter_RNG() = default;

std::string Jitter_RNG::name() const {
   return "JitterRNG";
}

bool Jitter_RNG::is_seeded() const {
   return true;
}

bool Jitter_RNG::accepts_input() const {
   return false;
}

void Jitter_RNG::clear() {}

void Jitter_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   m_jitter->collect_into_buffer(out);
}
};  // namespace Botan
