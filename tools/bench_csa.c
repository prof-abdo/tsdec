/* Throughput comparison: scalar single-packet CSA vs bitsliced batch CSA.
 * Same data, same key, same amount of work; only the engine differs.
 *
 * Note the per-iteration re-flagging of the scrambling bits: csa_decrypt()
 * clears them, so without it every rep after the first would measure nothing
 * but a branch. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "csa.h"

#define PCKTSIZE 188

static unsigned long rngstate = 88172645463325252UL;

static unsigned char nextrand(void)
{
   rngstate ^= rngstate << 13;
   rngstate ^= rngstate >> 7;
   rngstate ^= rngstate << 17;
   return (unsigned char)(rngstate);
}

static double now(void)
{
   return (double) clock() / (double) CLOCKS_PER_SEC;
}

int main(int argc, char **argv)
{
   static const unsigned char cw[8] =
      { 0x12, 0x34, 0x56, 0x9c, 0x78, 0x9a, 0xbc, 0x6e };
   int npkt = argc > 1 ? atoi(argv[1]) : 128 * 400;
   int reps = argc > 2 ? atoi(argv[2]) : 5;
   csa_ctx_t *ctx;
   unsigned char *buf;
   int *offsets;
   int i, r, bs;
   double t0, tscal, tbits;
   volatile long checksum = 0;

   bs = csa_bs_batch_size();
   buf = malloc((size_t) npkt * PCKTSIZE);
   offsets = malloc(sizeof(int) * (size_t) npkt);
   ctx = csa_ctx_new();
   if (!buf || !offsets || !ctx)
   {
      fprintf(stderr, "out of memory\n");
      return 1;
   }

   for (i = 0; i < npkt; i++)
   {
      int j;
      for (j = 0; j < PCKTSIZE; j++)
         buf[i * PCKTSIZE + j] = nextrand();
      buf[i * PCKTSIZE + 0] = 0x47;
      buf[i * PCKTSIZE + 3] = 0x80 | 0x10;
      buf[i * PCKTSIZE + 4] = 0x11;
      offsets[i] = i * PCKTSIZE;
   }

   csa_key_set_ctx(ctx, cw, 0);

   printf("payload : %d packets (%.1f MiB), batch size %d, %d reps\n",
          npkt, npkt * PCKTSIZE / 1048576.0, bs, reps);

   /* warm up */
   for (i = 0; i < npkt; i++)
      csa_decrypt_ctx(ctx, buf + offsets[i]);

   t0 = now();
   for (r = 0; r < reps; r++)
   {
      for (i = 0; i < npkt; i++)
         buf[offsets[i] + 3] |= 0x80;
      for (i = 0; i < npkt; i++)
         csa_decrypt_ctx(ctx, buf + offsets[i]);
      checksum += buf[17];
   }
   tscal = (now() - t0) / reps;

   t0 = now();
   for (r = 0; r < reps; r++)
   {
      for (i = 0; i < npkt; i++)
         buf[offsets[i] + 3] |= 0x80;
      for (i = 0; i < npkt; i += bs)
      {
         int n = npkt - i;
         if (n > bs)
            n = bs;
         csa_bs_decrypt_ctx(ctx, buf + i * PCKTSIZE, offsets, n, 0);
      }
      checksum += buf[17];
   }
   tbits = (now() - t0) / reps;

   printf("scalar  : %8.2f ms  %8.1f MiB/s  %9.0f pkt/s\n",
          tscal * 1000.0, npkt * PCKTSIZE / 1048576.0 / tscal, npkt / tscal);
   printf("bitslice: %8.2f ms  %8.1f MiB/s  %9.0f pkt/s\n",
          tbits * 1000.0, npkt * PCKTSIZE / 1048576.0 / tbits, npkt / tbits);
   printf("speedup : %.2fx  (checksum %ld)\n", tscal / tbits, checksum);

   csa_ctx_free(ctx);
   free(buf);
   free(offsets);
   return 0;
}
