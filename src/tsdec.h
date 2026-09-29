/* TSDEC public interface */

#ifndef TSDEC_H
#define TSDEC_H

#define TSDEC_VERSION "2.0"

#define PCKTSIZE 188

typedef struct
{
   unsigned char parity;
   unsigned char cw[8];
} cw_t;

typedef struct
{
   cw_t *cws;
   int   count;
} cwl_t;

typedef struct
{
   unsigned long total_packets;
   unsigned long encrypted_packets;
   unsigned long decrypted_packets;
   unsigned long passthrough_packets;
   unsigned long sync_count;
   unsigned long resync_count;
   unsigned long corrupt_packets;
   unsigned long checksum_corrections;
   unsigned long dropped_packets;
} stats_t;

typedef enum {
   RET_OK      = 0,

   /* input transport stream */
   RET_INFILE_NOTOPEN = 10,
   RET_INFILE_MODERR,

   /* input control word log */
   RET_CWLOPEN        = 20,
   RET_CWLFILEOPEN,
   RET_TOOLESSCWS,
   RET_OUTOFMEMORY,

   /* output */
   RET_OUTFILEOPEN    = 30,

   /* decryption */
   RET_NOSYNC     = 50,
   RET_OUTOFCWS,
   RET_TSCORRUPT,
   RET_NOTCRYPTED,
   RET_EOF,
   RET_CANCELED,

   /* misc */
   RET_SELFTESTFAILED = 60,
   RET_USAGE,
   RET_BATCH
} tenReturnValue;

/* control word log */
int  cwl_load (const char *name, cwl_t *out, int fix_checksums, int verbose);
void cwl_free (cwl_t *cwl);

int decrypt_cwl_file (const char *ifile, const char *ofile, const cwl_t *cwl,
                      int cw_blocker, int verbose, int progress,
                      const int *pid_filter, int npid_filter,
                      int allow_resync, int nworkers, stats_t *stats);

/* how many worker threads this machine can usefully run */
int tsdec_default_workers (void);

int analyze_file (const char *ifile, int verbose, const int *pid_filter,
                  int npid_filter, stats_t *stats);

int ccw_file (const char *ifile, const char *ofile, const unsigned char *ccw,
              int encrypt, int verbose, stats_t *stats);

int csa_selftest (void);

extern int g_verbose;
void tsdec_log (int level, const char *fmt, ...);

#endif
