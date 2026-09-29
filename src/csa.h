/* CSA wrapper around LIBDVBCSA.
 *
 * Two paths are exposed:
 *
 *   csa_decrypt / csa_encrypt        one packet, scalar CSA
 *   csa_bs_decrypt / csa_bs_encrypt  up to 128 packets at once, bitsliced
 *
 * The bitslice path (FFdecsa, bundled under src/dvbcsa) transposes the bit
 * planes of a whole batch into SIMD registers and runs the CSA round function
 * once for the batch instead of once per packet. On SSE2 that is 128 packets
 * in flight, which is where the bulk of the speedup comes from.
 *
 * Key material lives in a caller supplied context rather than in globals, so
 * several threads can decrypt with different control words at the same time.
 * A default context is kept for the single threaded paths.
 */

#ifndef CSA_H
#define CSA_H

#define CSA_BATCH_MAX 128

typedef struct csa_ctx_s csa_ctx_t;

/* Allocate/free a decryption context (holds the two key schedules). */
csa_ctx_t *csa_ctx_new (void);
void       csa_ctx_free (csa_ctx_t *ctx);

/* Install a control word for the even (parity 0) or odd (parity 1) half. */
void csa_key_set_ctx (csa_ctx_t *ctx, const unsigned char *cw, unsigned char parity);

/* single packet */
void csa_decrypt_ctx (csa_ctx_t *ctx, unsigned char *pkt);
void csa_encrypt_ctx (csa_ctx_t *ctx, unsigned char *pkt, unsigned char use_odd);

/* batch: offsets[i] is the byte offset of the i-th 188 byte TS packet inside
 * buf. Packets that are not scrambled are skipped and left untouched; all
 * packets passed to one call must share the same key half. Returns how many
 * packets were actually processed. */
int csa_bs_decrypt_ctx (csa_ctx_t *ctx, unsigned char *buf,
                        const int *offsets, int n, unsigned char parity);
int csa_bs_encrypt_ctx (csa_ctx_t *ctx, unsigned char *buf,
                        const int *offsets, int n, unsigned char parity);

/* largest batch the bitslice engine will take */
int csa_bs_batch_size (void);

/* default (process wide) context, for single threaded callers */
void csa_key_set (const unsigned char *cw, unsigned char parity);
void csa_decrypt (unsigned char *pkt);
void csa_encrypt (unsigned char *pkt, unsigned char use_odd);

#endif
