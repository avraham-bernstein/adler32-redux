/*
FILE:ayb-adler.h
DESCRIP: Interface to the Avraham Y. Bernstein Adler32-Redux functions which
resolve the original flaws associated with the Adler32 hash function.
NAMING CONVENTION:
  In order not to conflict with the namespace of the famous cryptographer,
  Daniel J. Bernstein, whose algorithm names typically start with "djb" or "djbern",
  I have chosen the prefix "AYBern" or "ayb"
DATE: 2017-05-22T12:20:00Z
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
*/

GCC_ATTRIB(nothrow,nonnull,pure)
uint32_t AYBern_adlerHash32(const uint16_t * msg, uint32_t n);

GCC_ATTRIB(nothrow,nonnull,pure)
uint64_t AYBern_adlerHash64(const uint32_t * msg, uint32_t n);

GCC_ATTRIB(nothrow,nonnull,pure)
uint64_t AYBern_adlerHashCipherXorshift128_64(const uint32_t * msg, uint32_t n,
    const uint64_t iv[2], uint64_t seed);
