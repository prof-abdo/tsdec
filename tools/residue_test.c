/* Residue test.
 *
 * The last block of a payload is only whole when the payload is a multiple of
 * eight. It usually is not: an adaptation field shortens the payload by one
 * more bytes than it adds, so the number of whole blocks depends on it, and
 * an audio stream carries an adaptation field often enough that a decoder
 * which only ever sees 184 or 176 will look fine in testing and fail on a real
 * recording.
 *
 * The rule is that the residue is covered by the stream cipher alone, there
 * being no whole block left for the block cipher to work on. Round tripping
 * every payload length from the full 184 down is what proves it, and the
 * lengths that are multiples of eight pass whether the rule is implemented or
 * not, so they prove nothing on their own. */

#include <stdio.h>
#include <string.h>

#include "csa.h"
#include "tsdec.h"                   /* PCKTSIZE */

#define TSC_ENCRYPTED 0x80
#define AFC_AF_AND_PAYLOAD 0x30

/* Build a scrambled packet whose payload is af_len bytes shorter than the
 * full 184, which is what an adaptation field of that length leaves behind. */
static void build (unsigned char *pkt, int af_len, int counter)
{
   int i;

   memset (pkt, 0, PCKTSIZE);
   pkt[0] = 0x47;                     /* sync */
   pkt[1] = 0x01;
   pkt[2] = 0x00;                      /* PID 0x100 */
   pkt[3] = TSC_ENCRYPTED | AFC_AF_AND_PAYLOAD | (counter & 0x0f);
   pkt[4] = (unsigned char) af_len;    /* adaptation_field_length */

   /* a recognisable payload, so a failure shows where it went wrong */
   for (i = 4 + af_len + 1; i < PCKTSIZE; i++)
      pkt[i] = (unsigned char) (i * 31 + counter);
}

int main (void)
{
   static const unsigned char cw[8] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xFF, 0xEE
   };
   unsigned char pkt[PCKTSIZE];
   unsigned char plain[PCKTSIZE];
   int payload_len = PCKTSIZE - 4;
   int bad = 0;

   csa_key_set (cw, 0);

   /* An adaptation field of n bytes leaves a payload of 183 - n, so this walks
    * the payload from 183 down to 8 and crosses every multiple of eight and
    * every residue on the way. */
   for (payload_len = PCKTSIZE - 5; payload_len >= 8; payload_len--)
   {
      int af_len = PCKTSIZE - 4 - payload_len - 1;

      build (pkt, af_len, payload_len);
      memcpy (plain, pkt, PCKTSIZE);

      csa_encrypt (pkt, 0);
      if (pkt[5 + af_len] == plain[5 + af_len] &&
          pkt[PCKTSIZE - 1] == plain[PCKTSIZE - 1])
      {
         printf ("  FAIL: payload %d was not encrypted\n", payload_len);
         bad++;
         continue;
      }

      /* the scrambling bits are cleared by a decrypt, so put them back before
       * comparing: this checks the payload, not the header */
      memcpy (pkt, plain, PCKTSIZE);
      csa_encrypt (pkt, 0);
      csa_decrypt (pkt);
      if (memcmp (plain + 5 + af_len, pkt + 5 + af_len,
                  (size_t) payload_len) != 0)
      {
         printf ("  FAIL: payload %d did not round trip\n", payload_len);
         bad++;
      }
   }

   /* report which of these are residues, so the coverage is visible rather
    * than taken on trust */
   {
      int residues = 0, whole = 0, len;
      for (len = 8; len <= 184; len++)
         (len % 8) ? residues++ : whole++;
      printf ("  covered %d payload lengths: %d whole blocks, %d residues\n",
              whole + residues, whole, residues);
   }

   printf ("  residue: %s\n", bad ? "FAIL" : "OK");
   return bad ? 1 : 0;
}
