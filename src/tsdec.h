/* TSDEC public interface */

#ifndef TSDEC_H
#define TSDEC_H

#define TSDEC_VERSION "2.5"

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

/* Ask for the stop to come from a file appearing instead of from a signal.
 *
 * A caller with no console of its own, which is any GUI application on
 * Windows, cannot deliver a console control event: there is nowhere to
 * deliver it from, so the request either does nothing or arrives as a kill,
 * and a kill discards the packets already decrypted. Creating this file asks
 * for the same clean stop that Ctrl+C does, on every platform.
 *
 * Pass NULL to go back to signals only. Returns 0, or -1 if the path will not
 * fit in the small fixed buffer this keeps it in. */
int  tsdec_set_stop_file (const char *path);

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

/* Short sentence describing a return code, in English. Shared by the command
 * line and by --json so a front end never has to invent its own wording. */
const char *tsdec_status_text (int ret);

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

/* ------------------------------------------------------------------ *
 * program specific information
 * ------------------------------------------------------------------ *
 *
 * What is in a recording, as opposed to which pids are in it. A transport
 * stream carries a PAT that maps program numbers to pids holding a PMT, and a
 * PMT that lists the pids making up one program. Without reading them a
 * recording of several services is just a pile of interleaved control words,
 * which is why a single service was assumed until now.
 *
 * Nothing here depends on the payload being decrypted: the tables are
 * program specific information, which is a control structure and is not
 * scrambled even when the elementary streams beside it are. */

#define TSDEC_MAX_PROGRAMS 32
#define TSDEC_MAX_STREAMS   16

typedef struct
{
   int           type;        /* stream_type from the PMT */
   int           pid;
   char          name[24];    /* service name from the SDT, or a description */
} stream_t;

typedef struct
{
   int           program;     /* program_number from the PAT */
   int           pmt_pid;
   int           pcr_pid;
   int           nstreams;
   int           encrypted;   /* 1 when the PMT says a control word is used */
   char          name[32];
   stream_t      streams[TSDEC_MAX_STREAMS];
} program_t;

typedef struct
{
   int           nprograms;
   program_t     programs[TSDEC_MAX_PROGRAMS];
} programs_t;

/* Read the tables from a recording. Returns the number of programs found, 0 if
 * there is no PAT, or a negative tenReturnValue. quiet stops it complaining
 * about a recording that simply has no tables in it, which is a capture of one
 * elementary stream rather than a program. */
int programs_read (const char *ifile, programs_t *out, int quiet);

void programs_free (programs_t *p);

/* The pids belonging to one program, for handing to the pid filter. Returns
 * how many were written, which is capped at max. */
int programs_pids (const programs_t *p, int program, int *out, int max);

/* "video", "audio", "h.264" and so on, for a stream_type. */
const char *stream_type_name (int type);

int ccw_file (const char *ifile, const char *ofile, const unsigned char *ccw,
              int encrypt, int verbose, stats_t *stats);

int csa_selftest (void);

extern int g_verbose;
void tsdec_log (int level, const char *fmt, ...);

/* Monotonic seconds, for a front end computing an elapsed time or a rate.
 * Exposed because the clock the core uses is not the caller's business. */
double now_seconds_public (void);

/* Number of whole transport packets a file holds, 0 if it cannot be read.
 * A front end needs this to turn "packets done" into a percentage. */
unsigned long tsdec_packet_count (const char *path);

#endif
