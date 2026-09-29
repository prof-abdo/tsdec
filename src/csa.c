/* CSA wrapper around LIBDVBCSA. See csa.h for the interface. */

#include <stdlib.h>
#include <string.h>

#include "dvbcsa/dvbcsa.h"
#include "dvbcsa/dvbcsa_bs.h"
#include "csa.h"

#define PCKTSIZE 188

/* Payload length handed to CSA: 188 - 4 header bytes = 184, a multiple of 8
 * as dvbcsa requires. */
#define CSA_PAYLOAD 184

/* dvbcsa's own key struct is opaque here, so we keep our own copy of the
 * layout (mirrors dvbcsa_pv.h) and hand out pointers. */
typedef struct
{
   unsigned char cw[8];
   unsigned char cws[8];
   unsigned char sch[56];
} csa_key_t;

struct csa_ctx_s
{
   csa_key_t  key[2];                                   /* even, odd */
   struct dvbcsa_bs_key_s bs[2];
};

int csa_bs_batch_size (void)
{
   return BS_BATCH_SIZE;
}

csa_ctx_t *csa_ctx_new (void)
{
   csa_ctx_t *ctx = malloc(sizeof(csa_ctx_t));
   if (!ctx)
      return NULL;
   memset(ctx, 0, sizeof(*ctx));
   return ctx;
}

void csa_ctx_free (csa_ctx_t *ctx)
{
   if (ctx)
      free(ctx);
}

void csa_key_set_ctx (csa_ctx_t *ctx, const unsigned char *cw, unsigned char parity)
{
   dvbcsa_cw_t key_cw;

   if (!ctx)
      return;

   memcpy(key_cw, cw, 8);
   dvbcsa_key_set(key_cw, (struct dvbcsa_key_s *) &ctx->key[parity ? 1 : 0]);
   dvbcsa_bs_key_set(key_cw, &ctx->bs[parity ? 1 : 0]);
}

/* Byte offset of the scrambled payload, or -1 when there is nothing to do. */
static int payload_offset (const unsigned char *pkt)
{
   unsigned int off = 4;

   if ((pkt[3] & 0x80) == 0)
      return -1;                    /* not scrambled */

   if (pkt[3] & 0x20)               /* adaptation field present */
   {
      off += pkt[4] + 1;
      if (off + 8 > PCKTSIZE)
         return -1;
   }
   return (int) off;
}

void csa_decrypt_ctx (csa_ctx_t *ctx, unsigned char *pkt)
{
   int off = payload_offset(pkt);

   if (off < 0)
      return;

   dvbcsa_decrypt((struct dvbcsa_key_s *) &ctx->key[(pkt[3] & 0x40) ? 1 : 0],
                  pkt + off, PCKTSIZE - off);
   pkt[3] &= 0x3f;                  /* clear transport scrambling control */
}

void csa_encrypt_ctx (csa_ctx_t *ctx, unsigned char *pkt, unsigned char use_odd)
{
   int off;

   /* Only packets that already carry the transport scrambling bit are
    * encrypted. That mirrors what the feature is for: a recording made by a
    * front end card arrives with the TSC bits already set and a payload that
    * has been mangled with the wrong key, so re-encrypting it is the way to
    * undo that. Packets flagged as clear are left clear. */
   if ((pkt[3] & 0x80) == 0)
      return;

   off = payload_offset(pkt);
   if (off < 0)
   {
      pkt[3] &= 0x3f;
      return;
   }

   if (use_odd)
      pkt[3] |= 0x40;
   else
      pkt[3] &= ~0x40;

   dvbcsa_encrypt((struct dvbcsa_key_s *) &ctx->key[use_odd ? 1 : 0],
                  pkt + off, PCKTSIZE - off);
}

int csa_bs_decrypt_ctx (csa_ctx_t *ctx, unsigned char *buf,
                        const int *offsets, int n, unsigned char parity)
{
   struct dvbcsa_bs_batch_s batch[CSA_BATCH_MAX + 1];
   unsigned char *hdr[CSA_BATCH_MAX];
   int i, m = 0;

   if (n > csa_bs_batch_size())
      n = csa_bs_batch_size();

   for (i = 0; i < n; i++)
   {
      unsigned char *pkt = buf + offsets[i];
      int off = payload_offset(pkt);

      if (off < 0)
         continue;

      /* A batch must be uniform in parity: the engine gets a single key. */
      if (((pkt[3] & 0x40) ? 1 : 0) != parity)
         continue;

      batch[m].data = pkt + off;
      batch[m].len  = PCKTSIZE - off;
      hdr[m] = pkt;
      m++;
   }

   if (!m)
      return 0;

   batch[m].data = 0;
   batch[m].len  = 0;

   dvbcsa_bs_decrypt(&ctx->bs[parity ? 1 : 0], batch, CSA_PAYLOAD);

   for (i = 0; i < m; i++)
      hdr[i][3] &= 0x3f;

   return m;
}

int csa_bs_encrypt_ctx (csa_ctx_t *ctx, unsigned char *buf,
                        const int *offsets, int n, unsigned char parity)
{
   struct dvbcsa_bs_batch_s batch[CSA_BATCH_MAX + 1];
   int i, m = 0;

   if (n > csa_bs_batch_size())
      n = csa_bs_batch_size();

   for (i = 0; i < n; i++)
   {
      unsigned char *pkt = buf + offsets[i];
      int off;

      /* same rule as csa_encrypt_ctx: only already flagged packets */
      if ((pkt[3] & 0x80) == 0)
         continue;

      off = payload_offset(pkt);
      if (off < 0)
      {
         pkt[3] &= 0x3f;
         continue;
      }

      if (parity)
         pkt[3] |= 0x40;
      else
         pkt[3] &= ~0x40;

      batch[m].data = pkt + off;
      batch[m].len  = PCKTSIZE - off;
      m++;
   }

   if (!m)
      return 0;

   batch[m].data = 0;
   batch[m].len  = 0;

   dvbcsa_bs_encrypt(&ctx->bs[parity ? 1 : 0], batch, CSA_PAYLOAD);
   return m;
}

/* ---- default context for single threaded callers ---- */

static csa_ctx_t g_default_ctx;

static void default_ctx_ensure (void)
{
   static int done;
   if (!done)
   {
      memset(&g_default_ctx, 0, sizeof(g_default_ctx));
      done = 1;
   }
}

void csa_key_set (const unsigned char *cw, unsigned char parity)
{
   default_ctx_ensure();
   csa_key_set_ctx(&g_default_ctx, cw, parity);
}

void csa_decrypt (unsigned char *pkt)
{
   default_ctx_ensure();
   csa_decrypt_ctx(&g_default_ctx, pkt);
}

void csa_encrypt (unsigned char *pkt, unsigned char use_odd)
{
   default_ctx_ensure();
   csa_encrypt_ctx(&g_default_ctx, pkt, use_odd);
}
