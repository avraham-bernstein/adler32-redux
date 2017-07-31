/*
FILE: aybern-adler.c
DESCRIP: Alder32 Redux.
  The funcs in this file are my Avraham Y. Bernstein (AYBern) tweaks of the
  original https://en.wikipedia.org/wiki/Adler-32 hash sum algorithm invented by
  Mark Adler in 1995. Even though Alder32 is still commonly (?) used, it has
  absolutely ZERO cryptographic strength! My funcs overcome all
  the known flaws with the Alder algorithm while still retaining its core
  simplicity and speed. My POC stream cipher variation provides "good enough
  security" for many apps, while substituting a stronger cipher would increase
  security concomitantly.

  Here is the *core* of the Adler32 algorithm. Given a message of n bytes,
  {x1, x2, ..., xn}, the algorithm is the following:

    uint32_t sum = x1*1 + x2*2 + x3*3 + ... + xn*n

  Adler32's advantage is that it is extremely fast to compute, and it is order
  dependent. But it has the following 3 fundamental flaws:

  1. For short messages, less than 4K bytes, its bit spread/coverage is
      extremely poor, i.e. the sum that is computes does not use up all the
      available bit space in the variable where the sum is stored.
  2. Its bit diffusion is very poor. Changing a single bit in the message
      generates a minor change in the bits in the resulting sum.
  3. It is trivial to tamper with, i.e. for an attacker to generate a
      collision - which is another message with the same sum, even if the
      "attacker" happens to be a communication hardware glitch. I want to
      avoid any discussion about whether or not one can generate semantically
      meaningful collisions.

  We added 2 minor tweaks that correct the first 2 problems. The names of these
  new funcs are:

    uint32_t AYBern_adlerHash32(const uint16_t * msg, uint32_t n);
    uint64_t AYBern_adlerHash64(const uint32_t * msg, uint32_t n);

  These funcs still retain the speed and simplicitly of the core algorithm.
  But they can *safely* be used as hash funcs only in BENIGN environments where
  tampering is not expected to be a problem, and where the costs of tampering
  are low, e.g. compiler symbol table hash functions, and network equipment
  "arp" table (MAC address) hash functions.

  We corrected the 3rd problem by incorporating a stream cipher into the body
  of the main loop. Currently the POC is using a 64-bit cipher. For IoT apps,
  we should also consider using a 32-bit cipher. For the POC, we chose not to
  pursue the alternative of wrapping our function with a general cipher of the
  caller's choosing. It is less efficient due to the necessity of constructing a
  buffering mechanism, while the goal of the POC is to show efficiency. For the
  POC we chose the Xorshift 128-bit PRNG which is extremely fast, but is NOT a
  cryptographic strength PRNG. Our new func is called:

    uint64_t AYBern_adlerHashCipherXorshift128_64(const uint32_t * msg,
      uint32_t n, const uint64_t iv[2], uint64_t seed);

  The maximum security Xorshift128 provides is for messages up to a length of 16
  bytes. The next step up would be to upgrade to Xorshift 1024 or 4096 PRNGs which
  provide "good enough security" for messages up to 128 and 512 bytes respectively.
  The general principle is that the cryptographic strength of our stream cipher
  variation is based upon the cryptographic strength of the cipher that we choose
  to incorporate inside it. And of course the security level is highly dependent
  upon using good security practices, i.e. guarding the IV, and using random
  seeds.
NAMING CONVENTION:
  In order not to conflict with the namespace of the famous cryptographer,
  Daniel J. Bernstein, whose algorithm names typically start with djb or djbern,
  I have chosen the prefix "AYBern".
DATE: 2017-05-22T18:46:00Z
AUTHOR: Avraham DOT Bernstein AT gmail
COPYRIGHT (c) 2017 Avraham Bernstein, Jerusalem ISRAEL. All rights reserved.
LICENSE: Apache License, Version 2.0: https://opensource.org/licenses/Apache-2.0
  The details specified in the above license link are what is legally binding.
  But in plain English, I have placed this software in the public domain.
  Use it any way you like, as long as you give me attribution. If you have any
  comments or suggestions, or find or fix any bugs, then please contact me.
  CAVEAT EMPTOR! This is an evolving prototype designed for illustrative
  purposes. I am providing it to you for free AS IS with absolutely NO
  GUARANTEE OF MERCHANTABILITY and NO GUARANTEE OF FITNESS FOR ANY PURPOSE.
  If you would like me to provide you with an industrial strength version with
  a commercial guarantee then please contact me.
REVISIONS:
2017-05-22: 1.0.0: AB: new
2017-07-31: 1.0.1: AB: minor documenation update
*/

#include <stdint.h>
#include <assert.h>

#ifdef __GNUC__
#define GCC_ATTRIB(...) __attribute__((__VA_ARGS__))
#else
#define GCC_ATTRIB(...)
#endif

#ifdef __cplusplus
#define INLINE inline
#else
#define INLINE static inline
#endif

#include "ayb-adler.h"

/*
  The Xoroshiro128Plus_next() function that immediately follows was written in
  2016 by David Blackman and Sebastiano Vigna (vigna@acm.org).

  Ref: http://prng.di.unimi.it/

  To the extent possible under law, the authors of this function have dedicated
  all copyright and related and neighboring rights to this software to the
  public domain worldwide. This software is distributed without any warranty.

  See: http://creativecommons.org/publicdomain/zero/1.0/

  This is the successor to xorshift128+. It is the fastest full-period
  generator passing BigCrush without systematic failures, but due to the
  relatively short period it is acceptable only for applications with a
  mild amount of parallelism; otherwise, use a xorshift1024* generator.

  Beside passing BigCrush, this generator passes the PractRand test suite
  up to (and included) 16TB, with the exception of binary rank tests,
  which fail due to the lowest bit being an LFSR; all other bits pass all
  tests. We suggest to use a sign test to extract a random Boolean value.

  Note that the generator uses a simulated rotate operation, which most C
  compilers will turn into a single instruction. In Java, you can use
  Long.rotateLeft(). In languages that do not make low-level rotation
  instructions accessible xorshift128+ could be faster.

  The state must be seeded so that it is not everywhere zero. If you have
  a 64-bit seed, we suggest to seed a splitmix64 generator and use its
  output to fill s.
*/

GCC_ATTRIB(nothrow,const)
INLINE uint64_t rotl64(uint64_t x, int k)
{
  return (x << k) | (x >> (64 - k));
}

GCC_ATTRIB(nothrow,const,unused)
INLINE uint32_t rotl32(uint32_t x, int k)
{
  return (x << k) | (x >> (32 - k));
}

GCC_ATTRIB(nothrow,const,unused)
INLINE uint16_t rotl16(uint16_t x, int k)
{
  return (x << k) | (x >> (16 - k));
}

// uint64_t s[2]; // AYBern: Originally the author S.V. used this global var

GCC_ATTRIB(nothrow,nonnull,flatten)
INLINE uint64_t Xoroshiro128Plus_next(uint64_t * s)
{
  // AYBern: Instead of the state, s, being declared as a global variable,
  // for our purposes we need it to be passed as a pointer.

  // AYBern: We chose to inline this func because it is being called in the
  // core loop where each character of the message is being processed.

  const uint64_t s0 = s[0];
  uint64_t s1 = s[1];
  const uint64_t result = s0 + s1;

  s1 ^= s0;
  s[0] = rotl64(s0, 55) ^ s1 ^ (s1 << 14); // a, b
  s[1] = rotl64(s1, 36); // c

  return result;
}

/*
  The SplitMix_next() function that immediately follows was written in 2015 by
  Sebastiano Vigna (vigna@acm.org).

  Ref: http://prng.di.unimi.it/

  To the extent possible under law, the author has dedicated all copyright
  and related and neighboring rights to this software to the public domain
  worldwide. This software is distributed without any warranty.

  See: http://creativecommons.org/publicdomain/zero/1.0/

  This is a fixed-increment version of Java 8's SplittableRandom generator
  See http://dx.doi.org/10.1145/2714064.2660195 and
  http://docs.oracle.com/javase/8/docs/api/java/util/SplittableRandom.html

  It is a very fast generator passing BigCrush, and it can be useful if
  for some reason you absolutely want 64 bits of state; otherwise, we
  rather suggest to use a xoroshiro128+ (for moderately parallel
  computations) or xorshift1024* (for massively parallel computations)
  generator.
*/

GCC_ATTRIB(nothrow,const)
static uint64_t SplitMix_next(uint64_t x)
{
  uint64_t z = (x += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31);
}

GCC_ATTRIB(nothrow,nonnull,unused,pure)
static uint32_t Adler32(const uint8_t * msg, uint32_t n)
{
  // This is the basic concept behind Adler32. It is *not* an exact copy of his algorithm.
  // This version is one that is useful for comparison purposes with the new algorithms.

  // max message len is 2^13 bytes = 8K

  assert(n <= (1 << 13));

  uint32_t adler_sum = 0;
  for(uint32_t i = 0; i < n; ++i) {
    adler_sum += (i+1) * msg[i];
  }

  return adler_sum;
}

GCC_ATTRIB(nothrow,nonnull,pure)
uint32_t AYBern_adlerHash32(const uint16_t * msg, uint32_t n)
{
  uint32_t hash_code = 0;

  const int32_t shift = 19; // 33 - 6 - 8
  const uint32_t block_len = 1 << (shift >> 1); // 2^9 uint16_t = 2^10 bytes

  uint32_t len = block_len;
  uint32_t n_blocks = n/block_len;
  uint32_t last_block_len = n & (block_len-1);
  if (last_block_len) ++n_blocks;

  // GOTCHYA: since our block sizes are 2^N by design, when we report that the
  // last_block_len is zero, in fact it means that it is full size,
  // i.e. block_len !

  const uint32_t lcg_c = 1013904223; // Numerical Recipes lcg32 prime > max(lcg_a)
  uint32_t lcg_a = 1;
  // all blocks except the last, are by definition full size so their lcg_a = 1
  uint32_t last_lcg_a = lcg_a;
  if (last_block_len) {
    last_lcg_a = (1 << shift)/(last_block_len * (last_block_len + 1));
    // satisfy Hull-Dobell multiplier constraint
    uint32_t hd_remainder = (last_lcg_a - 1) & 3;
    if (hd_remainder) last_lcg_a -= hd_remainder;
  }

  uint32_t i,j,k;

  for (j=0, k=0; j < n_blocks; ++j, k+=block_len) { // block loop: begin

    if (j == (n_blocks - 1)) {
      if (last_block_len) {
        len = last_block_len;
        lcg_a = last_lcg_a;
      }
    } // otherwise it is a full size block

    uint32_t adler_sum = 0;

    for (i = 0; i < len; ++i) {
        adler_sum += (i+1) * msg[i+k]; // retain original adler32 speed and simplicity
    }

    // lcg: params selected to evenly spread the bits over the whole 2^32 space

    uint32_t lcg = lcg_c;
    if (lcg_a == 1) {
        lcg += adler_sum;
    } else {
        lcg += adler_sum * lcg_a; // spread the bits for smaller block sizes
    }

    // block chain with order dependencies

    hash_code ^= (j & 1) ? ~lcg : lcg; // block order dependency by using j

    // mix: "roll my own" mixer because SplitMix doesn't handle 32 bits

    // 1. Gray xform

    hash_code ^= hash_code >> 1;

    // 2. double Rivest DDR

    uint16_t lo = hash_code & 0xffff;
    uint16_t hi = hash_code >> 16;

    uint16_t lo_shift = (hi + (uint16_t)j) & 0xf; // block order dependency by using j
    uint16_t hi_shift = (lo + (uint16_t)~j) & 0xf; // block order dependency by using j

    hi = rotl16(hi, (int16_t)hi_shift);
    lo = rotl16(lo, (int16_t)lo_shift);

    // put humpty dumpty back together again

    hash_code = (uint32_t)lo | (uint32_t)(hi << 16);
  } // block loop: end

  return hash_code;
}

GCC_ATTRIB(nothrow,nonnull,pure)
uint64_t AYBern_adlerHash64(const uint32_t * msg, uint32_t n)
{
  uint64_t hash_code = 0;

  const int32_t shift = 35; // 65 - 6 - 8 - 16
  const uint32_t block_len = 1 << (shift >> 1); // 2^17 uint32_t = 2^19 bytes = 512K bytes

  uint32_t len = block_len;
  uint32_t n_blocks = n/block_len;
  uint32_t last_block_len = n & (block_len-1);
  if (last_block_len) ++n_blocks;

  // GOTCHYA: since our block sizes are 2^N by design, when we report that the
  // last_block_len is zero, in fact it means that it is full size,
  // i.e. block_len !

  const uint64_t lcg_c = UINT64_C(1442695040888963407); // Knuth lcg64. It is not prime
  uint64_t lcg_a = 1;
  uint64_t last_lcg_a = lcg_a;
  // all blocks except the last, are by definition full size so their lcg_a = 1
  if (last_block_len) {
    last_lcg_a = (UINT64_C(1) << shift)/((uint64_t)last_block_len * (last_block_len + 1));
    // satisfy Hull-Dobell multiplier constraint
    uint64_t hd_remainder = (last_lcg_a - 1) & 3;
    if (hd_remainder) last_lcg_a -= hd_remainder;
  }

  uint32_t i,j,k;

  for (j=0, k=0; j < n_blocks; ++j, k+=block_len) { // block loop: begin

    if (j == (n_blocks - 1)) {
      if (last_block_len) {
        len = last_block_len;
        lcg_a = last_lcg_a;
      }
    } // otherwise it is a full size block

    uint64_t adler_sum = 0;

    for (i = 0; i < len; ++i) {
      adler_sum += (uint64_t)(i+1) * (uint64_t)msg[i+k]; // retain original adler32 speed and simplicity
    }

    // lcg: params selected to evenly spread the bits over the whole 2^64 space

    uint64_t lcg = lcg_c;
    if (lcg_a == UINT64_C(1)) {
        lcg += adler_sum;
    } else {
        lcg += adler_sum * lcg_a; // spread the bits for smaller block sizes
    }

    // block chain with order dependencies

    hash_code ^= lcg;

    // mix: SplitMix is a fanatastic mixer - without being heavy

    hash_code = SplitMix_next(hash_code + (uint64_t)j); // block order dependency by using j
  } // block loop: end

  return hash_code;
}

GCC_ATTRIB(nothrow,nonnull,pure)
uint64_t AYBern_adlerHashCipherXorshift128_64(const uint32_t * msg, uint32_t n, const uint64_t iv[2], uint64_t seed)
{
  uint64_t hash_code = 0;

  const int32_t shift = 35; // 65 - 6 - 8 - 16
  const uint32_t block_len = 1 << (shift >> 1); // 2^17 uint32_t = 2^19 bytes = 512K bytes

  uint32_t len = block_len;
  uint32_t n_blocks = n/block_len;
  uint32_t last_block_len = n & (block_len-1);
  if (last_block_len) ++n_blocks;

  const uint64_t lcg_c = UINT64_C(1442695040888963407); // Knuth lcg64. It is not prime
  uint64_t lcg_a = 1;
  uint64_t last_lcg_a = lcg_a;
  if (last_block_len) {
    last_lcg_a = (UINT64_C(1) << shift)/((uint64_t)last_block_len * (last_block_len + 1));
    // satisfy Hull-Dobell multiplier constraint
    uint64_t hd_remainder = (last_lcg_a - 1) & 3;
    if (hd_remainder) last_lcg_a -= hd_remainder;
  }

  // temper the iv
  uint64_t s[2] = { SplitMix_next(iv[0]^seed), SplitMix_next(iv[1]) };

  union {
    uint64_t r64;
    uint32_t r32[2];
  } un;

  uint32_t i,j,k;

  for (k=0, j=0; j < n_blocks; ++j, k+=block_len) { // block loop: begin

    if (j == (n_blocks - 1)) {
      if (last_block_len) {
        len = last_block_len;
        lcg_a = last_lcg_a;
      }
    }

    uint32_t parity = 1;

    uint64_t adler_sum = 0;

    for (i = 0; i < len; ++i) {
      parity = 1 - parity;

      if (parity == 0) {
        un.r64 = Xoroshiro128Plus_next(s); // prepare 64-bit mask from PRNG to be used similar to a stream cipher
      }

      adler_sum += (uint64_t)(i+1) * (uint64_t)(msg[i+k] ^ un.r32[parity]); // apply PRNG mask 32 bits at a time
    }

    // lcg

    uint64_t lcg = lcg_c;
    if (lcg_a == UINT64_C(1)) {
        lcg += adler_sum;
    } else {
        lcg += adler_sum * lcg_a;
    }

    // block chain

    hash_code ^= lcg;

    // mix

    hash_code = SplitMix_next(hash_code + (uint64_t)j); // block order dependency by using j
  } // block loop: end

  return hash_code;
}

#ifdef TEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
  const uint64_t iv[2] = { 972546410955, 972507515111 };

  uint8_t s1[16] = {
    0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
    0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0
  };

  uint8_t s2[16] = { // 1-bit change in lowest bit
    0x01,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
    0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0
  };

  uint8_t s3[16] = { // 1-bit change in hightest bit
    0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
    0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf1
  };

  union {
    uint8_t  s8[sizeof(s1)];
    uint16_t s16[sizeof(s1)/2];
    uint32_t s32[sizeof(s1)/4];
  } un1, un2, un3;

  memcpy(un1.s8,s1,sizeof(s1));
  memcpy(un2.s8,s2,sizeof(s2));
  memcpy(un3.s8,s3,sizeof(s3));

  uint32_t hash32a, hash32b, hash32c, hi, lo;
  uint64_t hash64;

  hash32a = Adler32(un1.s8,sizeof(s1));
  printf("Adler-1  = %08x\n",hash32a);
  hash32b = Adler32(un2.s8,sizeof(s2));
  printf("Adler-2  = %08x delta=%08x\n",hash32b, hash32b ^ hash32a);
  hash32c = Adler32(un3.s8,sizeof(s3));
  printf("Adler-3  = %08x delta=%08x\n",hash32c, hash32c ^ hash32a);

  hash32a = AYBern_adlerHash32(un1.s16,sizeof(s1)/2);
  printf("32-1     = %08x\n",hash32a);
  hash32b = AYBern_adlerHash32(un2.s16,sizeof(s2)/2);
  printf("32-2     = %08x delta=%08x\n",hash32b, hash32b ^ hash32a);
  hash32c = AYBern_adlerHash32(un3.s16,sizeof(s3)/2);
  printf("32-3     = %08x delta=%08x\n",hash32c, hash32c ^ hash32a);

  hash64 = AYBern_adlerHash64(un1.s32,sizeof(s1)/4);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-1     = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHash64(un2.s32,sizeof(s2)/4);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-2     = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHash64(un3.s32,sizeof(s3)/4);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-3     = %08x%08x\n",hi,lo);

  hash64 = AYBern_adlerHashCipherXorshift128_64(un1.s32,sizeof(s1)/4,iv,0);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-1a   = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHashCipherXorshift128_64(un2.s32,sizeof(s2)/4,iv,0);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-2a   = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHashCipherXorshift128_64(un3.s32,sizeof(s3)/4,iv,0);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-3a   = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHashCipherXorshift128_64(un1.s32,sizeof(s1)/4,iv,1);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-1b   = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHashCipherXorshift128_64(un2.s32,sizeof(s2)/4,iv,1);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-2b   = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHashCipherXorshift128_64(un3.s32,sizeof(s3)/4,iv,1);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-3b   = %08x%08x\n",hi,lo);

  hash64 = AYBern_adlerHashCipherXorshift128_64(un1.s32,sizeof(s1)/4,iv,5712234);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-1c   = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHashCipherXorshift128_64(un2.s32,sizeof(s2)/4,iv,5712234);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-2c   = %08x%08x\n",hi,lo);
  hash64 = AYBern_adlerHashCipherXorshift128_64(un3.s32,sizeof(s3)/4,iv,5712234);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("C64-3c   = %08x%08x\n",hi,lo);

  #define N (1 << 20)
  uint8_t * big = malloc(N);
  memset(big,1,N);

  hash32a = AYBern_adlerHash32((uint16_t *)big,512);
  printf("32-1K          = %08x\n",hash32a);
  hash32a = AYBern_adlerHash32((uint16_t *)big,1024);
  printf("32-2K          = %08x\n",hash32a);
  hash32a = AYBern_adlerHash32((uint16_t *)big,N/2);
  printf("32-1M          = %08x\n",hash32a);

  big[0] = 0; // change single lo bit
  hash32a = AYBern_adlerHash32((uint16_t *)big,512);
  printf("32-1K-lo-bit   = %08x\n",hash32a);
  hash32a = AYBern_adlerHash32((uint16_t *)big,1024);
  printf("32-2K-lo-bit   = %08x\n",hash32a);
  hash32a = AYBern_adlerHash32((uint16_t *)big,N/2);
  printf("32-1M-lo-bit   = %08x\n",hash32a);

  big[N-1] = 0; // change single hi bit
  hash32a = AYBern_adlerHash32((uint16_t *)big,512);
  printf("32-1K-hi-bit   = %08x\n",hash32a);
  hash32a = AYBern_adlerHash32((uint16_t *)big,1024);
  printf("32-2K-hi-bit   = %08x\n",hash32a);
  hash32a = AYBern_adlerHash32((uint16_t *)big,N/2);
  printf("32-1M-hi-bit   = %08x\n",hash32a);

  big[0] = 1; // restore changes
  big[N-1] = 1;

  hash64 = AYBern_adlerHash64((uint32_t *)big,N/8);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-17          = %08x%08x\n",hi,lo);

  hash64 = AYBern_adlerHash64((uint32_t *)big,N/4);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-18          = %08x%08x\n",hi,lo);

  big[0] = 0; // change single lo bit

  hash64 = AYBern_adlerHash64((uint32_t *)big,N/8);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-17-lo-bit   = %08x%08x\n",hi,lo);

  hash64 = AYBern_adlerHash64((uint32_t *)big,N/4);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-18-lo-bit   = %08x%08x\n",hi,lo);

  big[N-1] = 0; // change single hi-bit

  hash64 = AYBern_adlerHash64((uint32_t *)big,N/8);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-17-hi-bit   = %08x%08x\n",hi,lo);

  hash64 = AYBern_adlerHash64((uint32_t *)big,N/4);
  hi = hash64 >> 32;
  lo = hash64 & 0xFFFFFFFF;
  printf("64-18-hi-bit   = %08x%08x\n",hi,lo);

  return 0;
}

#if 0
Build Command: $ gcc -DTEST aybern-adler.c

AYBern-AdlerHash Test Vector Ouput:

Adler-1  = 00005500
Adler-2  = 00005501 delta=00000001
Adler-3  = 00005510 delta=00000010
32-1     = 5f02470c
32-2     = 025feb85 delta=5d5dac89
32-3     = 5f4f201c delta=004d6710
64-1     = faa6ad7bd25f234a
64-2     = 76f15b5f5284d642
64-3     = 0ef880f3ccb9c0de
C64-1a   = ca605f1595260c0b
C64-2a   = b67f621c47c19ed3
C64-3a   = 7916d1019e6d829a
C64-1b   = 029c0948b3964f58
C64-2b   = 7a878617dc5b42d1
C64-3b   = ba50c55214f80258
C64-1c   = f375ee63a2c5eb86
C64-2c   = e243b03d4580a193
C64-3c   = 1877b8c138803a6b
32-1K          = 90a4e01c
32-2K          = 79bf9e62
32-1M          = bb13620f
32-1K-lo-bit   = 2149e21c
32-2K-lo-bit   = 90a4ac43
32-1M-lo-bit   = 1fcfb35a
32-1K-hi-bit   = 2149e21c
32-2K-hi-bit   = 90a4ac43
32-1M-hi-bit   = 1f4759ad
64-17          = cf76143848552f82
64-18          = 9887d4d23e2b9153
64-17-lo-bit   = e821b63d929e2ee6
64-18-lo-bit   = b3a9c1b57ffda7a4
64-17-hi-bit   = e821b63d929e2ee6
64-18-hi-bit   = 9e96c74a0888ad27

#endif // 0: test vector output

#endif // TEST
