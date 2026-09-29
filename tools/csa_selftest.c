/* Cross-check the bitsliced batch CSA path against the scalar path.
 *
 * The speedup is worthless if the two disagree by even one bit, so this is the
 * gate that has to pass before anything else is trusted. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "csa.h"

#define PCKTSIZE 188
#define NPKT     300

static unsigned char cipher[NPKT * PCKTSIZE];
static unsigned char scal[NPKT * PCKTSIZE];
static unsigned char bits[NPKT * PCKTSIZE];
static int offsets[NPKT];

static unsigned long rngstate = 12345;

static unsigned char nextrand(void)
{
   rngstate = rngstate * 6364136223846793005UL + 1442695040888963407UL;
   return (unsigned char)(rngstate >> 33);
}

static void build_cipher(void)
{
   int i;

   for (i = 0; i < NPKT * PCKTSIZE; i++)
      cipher[i] = nextrand();

   for (i = 0; i < NPKT; i++)
   {
      unsigned char *p = cipher + i * PCKTSIZE;
      p[0] = 0x47;                    /* sync byte */
      p[3] &= 0x3f;
      p[3] |= 0x10;                   /* adaptation field control: payload only */
      p[3] |= 0x80;                   /* transport scrambling on */
      p[4] = 0x11;
      offsets[i] = i * PCKTSIZE;
   }
}

static int run(int parity)
{
   /* a control word with valid DVB checksums in bytes 3 and 7 */
   static const unsigned char cw[8] =
      { 0x12, 0x34, 0x56, 0x9c, 0x78, 0x9a, 0xbc, 0x6e };
   csa_ctx_t *ctx = csa_ctx_new();
   int bs = csa_bs_batch_size();
   int i, bad = 0, n;

   if (!ctx)
      return 1;

   csa_key_set_ctx(ctx, cw, (unsigned char) parity);

   for (i = 0; i < NPKT; i++)
   {
      unsigned char *p = cipher + i * PCKTSIZE;
      if (parity)
         p[3] |= 0x40;
      else
         p[3] &= ~0x40;
   }

   memcpy(scal, cipher, sizeof(cipher));
   memcpy(bits, cipher, sizeof(cipher));

   for (i = 0; i < NPKT; i++)
      csa_decrypt_ctx(ctx, scal + i * PCKTSIZE);

   for (i = 0; i < NPKT; i += bs)
   {
      n = NPKT - i;
      if (n > bs)
         n = bs;
      if (csa_bs_decrypt_ctx(ctx, bits + i * PCKTSIZE, offsets, n,
                             (unsigned char) parity) != n)
      {
         printf("  batch at %d did not process %d packets\n", i, n);
         bad++;
      }
   }

   if (memcmp(scal, bits, sizeof(scal)) != 0)
   {
      for (i = 0; i < NPKT * PCKTSIZE; i++)
      {
         if (scal[i] != bits[i])
         {
            printf("  first difference at byte %d (packet %d, offset %d): "
                   "scalar=%02x bitslice=%02x\n",
                   i, i / PCKTSIZE, i % PCKTSIZE, scal[i], bits[i]);
            break;
         }
      }
      bad++;
   }

   csa_ctx_free(ctx);
   printf("  %s key: %s\n", parity ? "odd " : "even", bad ? "FAIL" : "OK");
   return bad;
}

int main(void)
{
   int bad;

   printf("CSA batch cross-check, batch size = %d packets\n", csa_bs_batch_size());

   build_cipher();
   bad  = run(0);
   bad += run(1);

   printf("RESULT: %s\n", bad ? "FAIL" : "PASS");
   return bad ? 1 : 0;
}
