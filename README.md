# README.md: Alder32 Redux Project

Implementation Status: working POC

This mini-C project is my tweak of the original [Adler32](https://en.wikipedia.org/wiki/Adler-32)
hash sum algorithm invented by Mark Adler in 1995.
Even though Alder32 is still commonly (?) used,
it has absolutely ZERO cryptographic strength!
My tweaks overcome all the known flaws with the Alder algorithm while still
retaining its core simplicity and speed. My POC stream cipher variation provides
"good enough security" for many apps, while substituting a stronger cipher would
increase security concomitantly.

Here is the *core* of the Adler32 algorithm. Given a message of n bytes,
{x1, x2, ..., xn}, the algorithm is the following:

```C
uint32_t sum = x1*1 + x2*2 + x3*3 + ... + xn*n
```

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
new functions are:

```C
uint32_t AYBern_adlerHash32(const uint16_t * msg, uint32_t n);
uint64_t AYBern_adlerHash64(const uint32_t * msg, uint32_t n);
```

These functions still retain the speed and simplicitly of the core algorithm.
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
POC we chose the [Xorshift 128-bit PRNG](http://prng.di.unimi.it/)
which is extremely fast, but is NOT a cryptographic strength PRNG. Our new func is called:

 ```C
uint64_t AYBern_adlerHashCipherXorshift128_64(const uint32_t * msg, uint32_t n,
    const uint64_t iv[2], uint64_t seed);
```

The maximum security Xorshift128 provides is for messages up to a length of 16
bytes. The next step up would be to upgrade to Xorshift 1024 or 4096 PRNGs which
provide "good enough security" for messages up to 128 and 512 bytes respectively.
The general principle is that the cryptographic strength of our stream cipher
variation is based upon the cryptographic strength of the cipher that we choose
to incorporate inside it. And of course the security level is highly dependent
upon using good security practices, i.e. guarding the IV, and using random seeds.

## The solution incorporated the following 4 elements:

1. In each block, bits were evenly spread over the whole 2^N space using an
[Linear Congruential Generation (LCG)](https://en.wikipedia.org/wiki/Linear_congruential_generator)
transformation where the multiplicative coefficient "a" was calculated on-the-fly
and block length dependent. (See details below).

2. Block chaining was order dependent.

3. Bit diffusion was achieved by using the highly efficient off-the-shelf bit mixer
"SplitMix" for the 64 bit version, and a home brew mixer for the 32-bit version.

4. Anti-tampering protection was accomplished via the stream cipher.

### Bit Spread Algorithm

Let's analyze the core algorithm again (in 32-bit space):

```C
uint32_t sum = x1*1 + x2*2 + x3*3 + ... + xn*n
```

In the case where the x's are bytes then the expected value of the sum is:

```C
sum = 0x80 * n * (n+1) / 2
```

which reduces to

```C
sum = 0x40 * n * (n+1)
```

We would like the expected value of sum to be 2^33 so it completely wraps once.
If the expected value were 2^32 then the bits would be binomially distributed,
whereas 2^33 generates a uniform distribution. Therefore the ideal block size "n"
can be calculated as follows:

```C
(1 << 27) = n * (n+1)
```

For algorithmic simplicity (in order to use bit masking techniques), we will
define the ideal block size as 2^13 bytes.


In the case where the block size n < 2^13, we need to find a Kn that will
evenly spread the bits such that
```C
(1 << 27) = Kn * n * (n+1)
```

This reduces to:

```C
Kn <= (1 << 27) / (n*(n+1))
```

In order to not "lose" any bits during the multiplication process, Kn
should be the largest Hull-Dobell coefficient which satisfies this constraint,
where Hull-Dobell constraints are used for selecting LCG coefficients.

```C
uint32_t lcg_a = (1 << 27) / (n*(n+1));
uint32_t hd_delta = (lcg_a - 1) % 4;
if (hd_delta) lcg_a -= hd_delta;
```

## Source Code Naming Convention

In order not to conflict with the namespace of the famous cryptographer,
[Daniel J. Bernstein](https://en.wikipedia.org/wiki/Daniel_J._Bernstein),
whose algorithm names typically start with "djb" or "djbern",
I have chosen the prefix "AYBern", and sometimes "ayb".

## --
<address>
<br>AUTHOR: Avraham DOT Bernstein AT gmail
<br>DATE: 2017-05-22T20:45:00Z
<br>Copyright (c) Avraham Bernstein, Jerusalem ISRAEL. All rights reserved.
<br>LICENSE: Apache License, Version 2.0: https://opensource.org/licenses/Apache-2.0
</address>
