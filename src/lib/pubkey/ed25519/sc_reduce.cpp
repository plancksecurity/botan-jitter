/*
* Ed25519
* (C) 2017 Ribose Inc
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ed25519_internal.h>

namespace Botan {

/*
Input:
  s[0]+256*s[1]+...+256^63*s[63] = s

Output:
  s[0]+256*s[1]+...+256^31*s[31] = s mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
  Overwrites s in place.
*/

void sc_reduce(uint8_t* s)
   {
   const uint32_t MASK = 0x1fffff;

   int64_t s0 = MASK & load_3(s);
   int64_t s1 = MASK & (load_4(s + 2) >> 5);
   int64_t s2 = MASK & (load_3(s + 5) >> 2);
   int64_t s3 = MASK & (load_4(s + 7) >> 7);
   int64_t s4 = MASK & (load_4(s + 10) >> 4);
   int64_t s5 = MASK & (load_3(s + 13) >> 1);
   int64_t s6 = MASK & (load_4(s + 15) >> 6);
   int64_t s7 = MASK & (load_3(s + 18) >> 3);
   int64_t s8 = MASK & load_3(s + 21);
   int64_t s9 = MASK & (load_4(s + 23) >> 5);
   int64_t s10 = MASK & (load_3(s + 26) >> 2);
   int64_t s11 = MASK & (load_4(s + 28) >> 7);
   int64_t s12 = MASK & (load_4(s + 31) >> 4);
   int64_t s13 = MASK & (load_3(s + 34) >> 1);
   int64_t s14 = MASK & (load_4(s + 36) >> 6);
   int64_t s15 = MASK & (load_3(s + 39) >> 3);
   int64_t s16 = MASK & load_3(s + 42);
   int64_t s17 = MASK & (load_4(s + 44) >> 5);
   int64_t s18 = MASK & (load_3(s + 47) >> 2);
   int64_t s19 = MASK & (load_4(s + 49) >> 7);
   int64_t s20 = MASK & (load_4(s + 52) >> 4);
   int64_t s21 = MASK & (load_3(s + 55) >> 1);
   int64_t s22 = MASK & (load_4(s + 57) >> 6);
   int64_t s23 = (load_4(s + 60) >> 3);

   s11 += s23 * 666643;
   s12 += s23 * 470296;
   s13 += s23 * 654183;
   s14 -= s23 * 997805;
   s15 += s23 * 136657;
   s16 -= s23 * 683901;
   s23 = 0;

   s10 += s22 * 666643;
   s11 += s22 * 470296;
   s12 += s22 * 654183;
   s13 -= s22 * 997805;
   s14 += s22 * 136657;
   s15 -= s22 * 683901;
   s22 = 0;

   s9 += s21 * 666643;
   s10 += s21 * 470296;
   s11 += s21 * 654183;
   s12 -= s21 * 997805;
   s13 += s21 * 136657;
   s14 -= s21 * 683901;
   s21 = 0;

   s8 += s20 * 666643;
   s9 += s20 * 470296;
   s10 += s20 * 654183;
   s11 -= s20 * 997805;
   s12 += s20 * 136657;
   s13 -= s20 * 683901;
   s20 = 0;

   s7 += s19 * 666643;
   s8 += s19 * 470296;
   s9 += s19 * 654183;
   s10 -= s19 * 997805;
   s11 += s19 * 136657;
   s12 -= s19 * 683901;
   s19 = 0;

   s6 += s18 * 666643;
   s7 += s18 * 470296;
   s8 += s18 * 654183;
   s9 -= s18 * 997805;
   s10 += s18 * 136657;
   s11 -= s18 * 683901;
   s18 = 0;

   carry<21>(s6, s7);
   carry<21>(s8, s9);
   carry<21>(s10, s11);
   carry<21>(s12, s13);
   carry<21>(s14, s15);
   carry<21>(s16, s17);

   carry<21>(s7, s8);
   carry<21>(s9, s10);
   carry<21>(s11, s12);
   carry<21>(s13, s14);
   carry<21>(s15, s16);

   s5 += s17 * 666643;
   s6 += s17 * 470296;
   s7 += s17 * 654183;
   s8 -= s17 * 997805;
   s9 += s17 * 136657;
   s10 -= s17 * 683901;
   s17 = 0;

   s4 += s16 * 666643;
   s5 += s16 * 470296;
   s6 += s16 * 654183;
   s7 -= s16 * 997805;
   s8 += s16 * 136657;
   s9 -= s16 * 683901;
   s16 = 0;

   s3 += s15 * 666643;
   s4 += s15 * 470296;
   s5 += s15 * 654183;
   s6 -= s15 * 997805;
   s7 += s15 * 136657;
   s8 -= s15 * 683901;
   s15 = 0;

   s2 += s14 * 666643;
   s3 += s14 * 470296;
   s4 += s14 * 654183;
   s5 -= s14 * 997805;
   s6 += s14 * 136657;
   s7 -= s14 * 683901;
   s14 = 0;

   s1 += s13 * 666643;
   s2 += s13 * 470296;
   s3 += s13 * 654183;
   s4 -= s13 * 997805;
   s5 += s13 * 136657;
   s6 -= s13 * 683901;
   s13 = 0;

   s0 += s12 * 666643;
   s1 += s12 * 470296;
   s2 += s12 * 654183;
   s3 -= s12 * 997805;
   s4 += s12 * 136657;
   s5 -= s12 * 683901;
   s12 = 0;

   carry<21>(s0, s1);
   carry<21>(s2, s3);
   carry<21>(s4, s5);
   carry<21>(s6, s7);
   carry<21>(s8, s9);
   carry<21>(s10, s11);

   carry<21>(s1, s2);
   carry<21>(s3, s4);
   carry<21>(s5, s6);
   carry<21>(s7, s8);
   carry<21>(s9, s10);
   carry<21>(s11, s12);

   s0 += s12 * 666643;
   s1 += s12 * 470296;
   s2 += s12 * 654183;
   s3 -= s12 * 997805;
   s4 += s12 * 136657;
   s5 -= s12 * 683901;
   s12 = 0;

   carry<21>(s0, s1);
   carry<21>(s1, s2);
   carry<21>(s2, s3);
   carry<21>(s3, s4);
   carry<21>(s4, s5);
   carry<21>(s5, s6);
   carry<21>(s6, s7);
   carry<21>(s7, s8);
   carry<21>(s8, s9);
   carry<21>(s9, s10);
   carry<21>(s10, s11);
   carry0<21>(s11, s12);

   s0 += s12 * 666643;
   s1 += s12 * 470296;
   s2 += s12 * 654183;
   s3 -= s12 * 997805;
   s4 += s12 * 136657;
   s5 -= s12 * 683901;
   s12 = 0;

   carry0<21>(s0, s1);
   carry0<21>(s1, s2);
   carry0<21>(s2, s3);
   carry0<21>(s3, s4);
   carry0<21>(s4, s5);
   carry0<21>(s5, s6);
   carry0<21>(s6, s7);
   carry0<21>(s7, s8);
   carry0<21>(s8, s9);
   carry0<21>(s9, s10);
   carry0<21>(s10, s11);

   s[0] = s0 >> 0;
   s[1] = s0 >> 8;
   s[2] = (s0 >> 16) | (s1 << 5);
   s[3] = s1 >> 3;
   s[4] = s1 >> 11;
   s[5] = (s1 >> 19) | (s2 << 2);
   s[6] = s2 >> 6;
   s[7] = (s2 >> 14) | (s3 << 7);
   s[8] = s3 >> 1;
   s[9] = s3 >> 9;
   s[10] = (s3 >> 17) | (s4 << 4);
   s[11] = s4 >> 4;
   s[12] = s4 >> 12;
   s[13] = (s4 >> 20) | (s5 << 1);
   s[14] = s5 >> 7;
   s[15] = (s5 >> 15) | (s6 << 6);
   s[16] = s6 >> 2;
   s[17] = s6 >> 10;
   s[18] = (s6 >> 18) | (s7 << 3);
   s[19] = s7 >> 5;
   s[20] = s7 >> 13;
   s[21] = s8 >> 0;
   s[22] = s8 >> 8;
   s[23] = (s8 >> 16) | (s9 << 5);
   s[24] = s9 >> 3;
   s[25] = s9 >> 11;
   s[26] = (s9 >> 19) | (s10 << 2);
   s[27] = s10 >> 6;
   s[28] = (s10 >> 14) | (s11 << 7);
   s[29] = s11 >> 1;
   s[30] = s11 >> 9;
   s[31] = s11 >> 17;
   }

}
