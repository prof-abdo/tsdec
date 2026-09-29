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
   int           canceled;           /* stopped on request, not on error */
} stats_t;

/* Called every so often while a long job runs, so a front end can show
 * progress and the user can still hit stop. total is the number of packets
 * the input holds (0 when unknown), done is how many have been processed. */
typedef void (*tsdec_progress_fn)(void *user, unsigned long done,
                                  unsigned long total, const stats_t *st);

/* Set from a signal handler or from another thread to ask the current job to
 * stop. It is honoured between blocks, so a job stops within a fraction of a
 * second rather than instantly. */
void tsdec_request_cancel (void);
int  tsdec_cancel_requested (void);
void tsdec_clear_cancel (void);

/* Install a handler so that Ctrl+C asks for a stop instead of killing the
 * process mid write. Returns 0 on success. */
int tsdec_install_sigint_handler (void);

typedef struct
{
   const char     *ifile;
   const char     *ofile;
   const cwl_t    *cwl;
   int              cw_blocker;
   int              verbose;
   int              progress;      /* 1: log progress to stderr */
   int              nworkers;      /* 0: work it out from the cpu count */
   int              allow_resync;
   const int       *pid_filter;
   int              npid_filter;

   /* optional, both may be NULL. When set, progress goes here instead of to
    * stderr, at a few times a second rather than every packet. */
   tsdec_progress_fn on_progress;
   void             *progress_user;
} tsdec_job_t;

/* Fill in sensible defaults for anything the caller left at zero. */
void tsdec_job_init (tsdec_job_t *job);


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

/* Main entry point. See tsdec_job_t; the arguments on the old interface are
 * folded into it. progress may be 0, in which case no callback fires. */
int tsdec_run (const tsdec_job_t *job, stats_t *stats);

/* Convenience wrapper for the command line path. */
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
