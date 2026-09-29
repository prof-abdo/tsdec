/*
 * libdvbcsa build configuration for tsdec.
 *
 * The original file shipped a hand-rolled MSVC configuration that typedef'd
 * size_t/uintN_t by hand and #define'd away `inline`, which breaks on any
 * C99 compiler. We use the standard headers instead and select the bitslice
 * word size based on the target architecture.
 */

#ifndef DVBCSA_CONFIG_H_
#define DVBCSA_CONFIG_H_

#define STDC_HEADERS 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STDINT_H 1

/* Bitslice word size: 128-bit SSE2 processes 128 packets per batch,
 * 64-bit SSE processes 64. Prefer the widest available. */
#if defined(DVBCSA_USE_UINT32)
  /* user override: keep whatever was requested */
#elif defined(__AVX__) || defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
# define DVBCSA_USE_SSE 1
#elif defined(__MMX__) || defined(_M_IX86)
# define DVBCSA_USE_MMX 1
#else
# define DVBCSA_USE_UINT32 1
#endif

#endif
