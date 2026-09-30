/* TSDEC core: offline decrypter for recorded DVB transport streams.
 *
 * Layout of this file:
 *
 *   cwl_load              parse and sanity check a control word log
 *   decrypt_cwl_file      main path: sync, then decrypt
 *   analyze_file          PID survey, no decryption
 *   ccw_file              constant control word encrypt/decrypt
 *
 * Performance notes. The original did one fread() plus one scalar CSA pass per
 * 188 byte packet. Here the input is read in ~1 MiB blocks, the sync decision
 * is taken for every packet in a block first, and the resulting runs of
 * same-parity packets are handed to the bitsliced CSA engine in batches of up
 * to 128 packets (see csa.c). Splitting "decide" from "decrypt" is what makes
 * the batching possible, and it is also what makes the code thread friendly.
 */

#define _FILE_OFFSET_BITS 64

#ifdef __APPLE__
#include <mach/mach_time.h>
#include <stdint.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

#include "csa.h"
#include "tsdec.h"
#include "thread.h"

int g_verbose = 2;

/* ------------------------------------------------------------------ *
 * cancellation
 * ------------------------------------------------------------------ *
 *
 * The flag is written from a signal handler, so it has to be a plain
 * sig_atomic_t rather than anything atomic-aware. The job polls it between
 * blocks, which is where the responsiveness actually comes from: a block is
 * about a megabyte, so the worst case is the time to finish the block in
 * flight rather than the time to drain a queue.
 */
static volatile sig_atomic_t g_cancel = 0;

/* An optional file whose presence means "stop". A front end creates it to ask
 * for a stop without needing a console.
 *
 * This exists because the console control event is not available to every
 * caller. A GUI application on Windows has no console of its own, and
 * GenerateConsoleCtrlEvent has nowhere to deliver the event from, so a stop
 * sent that way either does nothing or degrades into a kill, and a kill throws
 * away every packet already decrypted. A file works the same on every
 * platform and does not care whether anybody is attached to a terminal. */
static char g_stop_file[260] = { 0 };

static void on_sigint (int sig)
{
   (void) sig;
   g_cancel = 1;
}

void tsdec_request_cancel (void)
{
   g_cancel = 1;
}

int tsdec_cancel_requested (void)
{
   if (g_cancel)
      return 1;

   /* asking a few times a second is cheap next to decrypting a block, and it
    * is the only way a caller with no console can ask at all */
   if (g_stop_file[0])
   {
      FILE *f = fopen(g_stop_file, "rb");
      if (f)
      {
         fclose(f);
         g_cancel = 1;
      }
   }

   return g_cancel != 0;
}

void tsdec_clear_cancel (void)
{
   g_cancel = 0;
}

int tsdec_set_stop_file (const char *path)
{
   if (!path || !path[0])
   {
      g_stop_file[0] = 0;
      return 0;
   }
   if (strlen(path) >= sizeof(g_stop_file))
      return -1;
   strcpy(g_stop_file, path);
   return 0;
}

int tsdec_install_sigint_handler (void)
{
#ifdef _WIN32
   /* Windows turns Ctrl+C off for any process that was started with
    * CREATE_NEW_PROCESS_GROUP, which is exactly what a parent does so it can
    * target this child without hitting itself. Turn it back on, otherwise the
    * control event terminates us outright and whatever was already decrypted
    * is lost. Harmless when we were not started as a group leader. */
   SetConsoleCtrlHandler(NULL, FALSE);
   return signal(SIGINT, on_sigint) == SIG_ERR ? -1 : 0;
#else
   struct sigaction sa;

   memset(&sa, 0, sizeof(sa));
   sa.sa_handler = on_sigint;
   sigemptyset(&sa.sa_mask);
   /* no SA_RESTART: a blocking read should come back so the poll happens */
   sa.sa_flags = 0;
   return sigaction(SIGINT, &sa, NULL) == 0 ? 0 : -1;
#endif
}

const char *tsdec_status_text (int ret)
{
   switch (ret)
   {
      case RET_OK:
         return "done";
      case RET_INFILE_NOTOPEN:
         return "the recording could not be opened";
      case RET_INFILE_MODERR:
         return "the recording changed while it was being read";
      case RET_CWLOPEN:
         return "the control word log could not be read";
      case RET_CWLFILEOPEN:
         return "the control word log file could not be opened";
      case RET_TOOLESSCWS:
         return "the control word log has no usable control words";
      case RET_OUTOFMEMORY:
         return "out of memory";
      case RET_OUTFILEOPEN:
         return "the output file could not be written";
      case RET_NOSYNC:
         return "could not sync the control word log to this recording";
      case RET_OUTOFCWS:
         return "the control word log ran out before the recording";
      case RET_TSCORRUPT:
         return "the transport stream is too damaged to read";
      case RET_NOTCRYPTED:
         return "the recording holds no encrypted packets";
      case RET_EOF:
         return "unexpected end of file";
      case RET_CANCELED:
         return "stopped on request, the work already done was kept";
      case RET_SELFTESTFAILED:
         return "the cipher self test failed";
      case RET_USAGE:
         return "bad command line";
      case RET_BATCH:
         return "batched runs are not supported";
      default:
         return "failed";
   }
}

void tsdec_log (int level, const char *fmt, ...)
{
   va_list ap;

   if (level > g_verbose)
      return;

   fprintf(stderr, "TSDEC: ");
   va_start(ap, fmt);
   vfprintf(stderr, fmt, ap);
   va_end(ap);

   /* Callers do not spell out the line ending, so it is added here. Without
    * this every message runs into the next one, which is invisible on a
    * terminal but makes the output unparsable when it is a pipe, which is
    * exactly how a front end reads it. */
   fputc('\n', stderr);
}

/* ------------------------------------------------------------------ *
 * control word log
 * ------------------------------------------------------------------ */

/* A DVB control word is two 4 byte halves, each closed by an additive
 * checksum. Loggers routinely get these wrong, so repair rather than refuse. */
static int fix_cw_checksums (unsigned char *cw)
{
   unsigned char c0 = (unsigned char) (cw[0] + cw[1] + cw[2]);
   unsigned char c1 = (unsigned char) (cw[4] + cw[5] + cw[6]);
   int changed = 0;

   if (cw[3] != c0) { cw[3] = c0; changed = 1; }
   if (cw[7] != c1) { cw[7] = c1; changed = 1; }
   return changed;
}

/* Does this line start with something we can use? */
static int is_skippable (const char *line)
{
   const char *p = line;
   while (*p && isspace((unsigned char) *p))
      p++;
   return *p == 0 || *p == '#' || *p == ';' || *p == '*' || *p == '!';
}

int cwl_load (const char *name, cwl_t *out, int fix_checksums, int verbose)
{
   FILE *f;
   char line[256];
   int cap = 64, n = 0, line_no = 0, last_parity = -1, fixed = 0;
   cw_t *cws;

   out->cws = NULL;
   out->count = 0;

   if (!(f = fopen(name, "r")))
   {
      tsdec_log(0, "cannot open cwl file %s", name);
      return RET_CWLFILEOPEN;
   }

   cws = malloc(sizeof(cw_t) * (size_t) cap);
   if (!cws)
   {
      fclose(f);
      return RET_OUTOFMEMORY;
   }

   while (fgets(line, sizeof(line), f))
   {
      int par = 0, a[8], k, got;

      ++line_no;
      if (is_skippable(line))
         continue;

      /* Preferred form: leading parity, then eight hex bytes. */
      got = sscanf(line, "%d %x %x %x %x %x %x %x %x",
                   &par, &a[0], &a[1], &a[2], &a[3],
                   &a[4], &a[5], &a[6], &a[7]);

      if (got != 9)
      {
         /* Some loggers write the key as one 16 digit run, with no parity
          * column. Recover the parity from which half has a valid checksum. */
         char hex[40] = "";
         unsigned int v;
         int j, ok = 0;

         got = sscanf(line, "%39s", hex);
         if (got == 1)
         {
            const char *h = hex;
            if (*h == '0' && (h[1] == 'x' || h[1] == 'X'))
               h += 2;
            if (strlen(h) == 16 &&
                sscanf(h, "%8x", &v) == 1)
            {
               for (j = 0; j < 8; j++)
                  a[j] = (int) ((v >> (8 * (7 - j))) & 0xFF);
               par = (a[3] == ((a[0] + a[1] + a[2]) & 0xFF)) ? 0 : 1;
               ok = 1;
            }
         }

         if (!ok)
         {
            tsdec_log(3, "cwl line %d not understood, ignored: %s", line_no, line);
            continue;
         }
      }

      for (k = 0; k < 8; k++)
         a[k] &= 0xFF;

      if (par != 0 && par != 1)
      {
         tsdec_log(3, "cwl line %d has invalid parity %d, ignored", line_no, par);
         continue;
      }

      if (last_parity == par)
         tsdec_log(2, "cwl line %d repeats parity %d; this can break sync",
                   line_no, par);
      last_parity = par;

      if (fix_checksums)
      {
         unsigned char raw[8];
         for (k = 0; k < 8; k++)
            raw[k] = (unsigned char) a[k];
         if (fix_cw_checksums(raw))
         {
            for (k = 0; k < 8; k++)
               a[k] = raw[k];
            fixed++;
         }
      }

      if (n == cap)
      {
         cw_t *bigger;
         cap *= 2;
         bigger = realloc(cws, sizeof(cw_t) * (size_t) cap);
         if (!bigger)
         {
            free(cws);
            fclose(f);
            return RET_OUTOFMEMORY;
         }
         cws = bigger;
      }

      cws[n].parity = (unsigned char) par;
      for (k = 0; k < 8; k++)
         cws[n].cw[k] = (unsigned char) a[k];
      n++;

      if (verbose >= 5)
      {
         char hx[24];
         int j;
         for (j = 0; j < 8; j++)
            sprintf(hx + j * 2, "%02X", cws[n - 1].cw[j]);
         tsdec_log(5, "cwl #%d parity %d %s", n - 1, par, hx);
      }
   }

   fclose(f);

   if (n == 0)
   {
      free(cws);
      tsdec_log(2, "%s contains no usable control words", name);
      return RET_TOOLESSCWS;
   }
   if (n < 2)
      tsdec_log(2, "%s holds a single control word; sync is unlikely to work", name);

   out->cws = cws;
   out->count = n;
   if (fixed)
      tsdec_log(2, "%d control word checksums corrected", fixed);

   tsdec_log(2, "%s: %d control words loaded", name, n);
   return RET_OK;
}

void cwl_free (cwl_t *cwl)
{
   if (cwl && cwl->cws)
   {
      free(cwl->cws);
      cwl->cws = NULL;
      cwl->count = 0;
   }
}

/* ------------------------------------------------------------------ *
 * transport stream helpers
 * ------------------------------------------------------------------ */

#define IsPUSIPacket(p)      (((p)[1] & 0x40) == 0x40)
#define IsEncryptedPacket(p) (((p)[3] & 0x80) == 0x80)
#define GetPacketParity(p)   (((p)[3] & 0x40) == 0x40)

static int packet_pid (const unsigned char *p)
{
   return ((p[1] & 0x1F) << 8) | p[2];
}

static int pid_selected (int pid, const int *filter, int nfilter)
{
   int i;
   if (!filter || nfilter <= 0)
      return 1;
   for (i = 0; i < nfilter; i++)
      if (filter[i] == pid)
         return 1;
   return 0;
}

/* Validates the adaptation field length before trusting the payload offset,
 * otherwise a malformed header would send us into the middle of the payload. */
static int packet_has_pes_header (const unsigned char *p)
{
   unsigned int off = 4;
   unsigned int afc = (p[3] >> 4) & 3;

   if (afc == 3)
   {
      if (p[4] > PCKTSIZE - off - 4)
         return 0;
      off += p[4] + 1;
   }
   else if (afc == 2 || afc == 0)
   {
      return 0;                 /* adaptation only, or reserved */
   }

   if (off + 3 > PCKTSIZE)
      return 0;

   return p[off] == 0x00 && p[off + 1] == 0x00 && p[off + 2] == 0x01;
}

#define BLOCK_PACKETS 5461          /* ~1 MiB of transport stream */

/* Blocked reader: one fread() per packet dominated the original's runtime. */
typedef struct
{
   FILE          *fp;
   unsigned char *buf;
   size_t         cap;
   size_t         have;
   int            eof;
} reader_t;

static int reader_open (reader_t *r, const char *path, size_t cap_packets)
{
   r->fp = fopen(path, "rb");
   if (!r->fp)
      return RET_INFILE_NOTOPEN;
   r->cap = cap_packets;
   r->buf = malloc(r->cap * PCKTSIZE);
   if (!r->buf)
   {
      fclose(r->fp);
      r->fp = NULL;
      return RET_OUTOFMEMORY;
   }
   r->have = 0;
   r->eof = 0;
   return RET_OK;
}

static void reader_close (reader_t *r)
{
   if (r->fp) fclose(r->fp);
   if (r->buf) free(r->buf);
   r->fp = NULL;
   r->buf = NULL;
}

/* Fills the block. Returns the number of whole packets available, 0 at EOF. */
static size_t reader_fill (reader_t *r)
{
   size_t got;

   if (r->eof)
      return 0;

   got = fread(r->buf, PCKTSIZE, r->cap, r->fp);
   if (got < r->cap)
      r->eof = 1;

   r->have = got;
   return got;
}

#ifdef __APPLE__
static mach_timebase_info_data_t mach_base;
static double mach_per_tick;

static void mach_tick_setup (void)
{
   if (mach_timebase_info(&mach_base) == KERN_SUCCESS && mach_base.denom != 0)
      /* as a double: the ratio is not always whole, and rounding it to an
       * integer first would skew every measurement that follows */
      mach_per_tick = (double) mach_base.numer / (double) mach_base.denom;
}
#endif

/* Wall clock, because everything derived from it is user facing: the
 * throughput figure and the estimate of how much is left.
 *
 * clock() is the trap here. It returns processor time, so on POSIX it sums
 * across every worker thread: an eight thread run that takes a second of real
 * time would be reported as eight, and the throughput would come out roughly
 * eight times too low with a wildly wrong ETA. The Windows CRT happens to
 * return wall clock time, which is why the bug hides on one platform only. */
static double now_seconds (void)
{
#ifdef _WIN32
   /* QPC is monotonic and unaffected by the wall clock being adjusted. It is
    * already the performance counter that GetTickCount reads underneath, so
    * there is no need for the older coarser fallback. */
   static LARGE_INTEGER freq;
   LARGE_INTEGER now;

   if (freq.QuadPart == 0)
      QueryPerformanceFrequency(&freq);
   QueryPerformanceCounter(&now);
   return (double) now.QuadPart / (double) freq.QuadPart;
#else
# ifdef __APPLE__
   /* the ratio never changes, so resolve it once however many workers ask */
   static pthread_once_t mach_once = PTHREAD_ONCE_INIT;

   pthread_once(&mach_once, mach_tick_setup);
   if (mach_per_tick != 0.0)
      return (double) mach_absolute_time() * mach_per_tick / 1e9;
# endif
   {
      struct timespec ts;

      if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
         return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
   }

   /* very old or exotic unix without clock_gettime */
   return (double) clock() / (double) CLOCKS_PER_SEC;
#endif
}

double now_seconds_public (void)
{
   return now_seconds();
}

/* How many whole packets the input holds. Used to turn "x packets done" into a
 * percentage and an estimate. Returns 0 if the size cannot be determined. */
static unsigned long reader_packet_count (const char *path);

unsigned long tsdec_packet_count (const char *path)
{
   return reader_packet_count(path);
}

static unsigned long reader_packet_count (const char *path)
{
   FILE *f;
   long long size;
   unsigned long count;

   if (!(f = fopen(path, "rb")))
      return 0;

#if defined(_WIN32)
   {
      __int64 pos = _ftelli64(f);
      if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
      size = (long long) _ftelli64(f);
      _fseeki64(f, pos, SEEK_SET);
   }
#else
   {
      off_t pos = ftello(f);
      if (fseeko(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
      size = (long long) ftello(f);
      fseeko(f, pos, SEEK_SET);
   }
#endif

   fclose(f);
   if (size <= 0)
      return 0;

   count = (unsigned long) (size / PCKTSIZE);
   return count;
}

static void report_stats (const stats_t *s, double secs)
{
   double mbps = secs > 0 ? (double) s->total_packets * PCKTSIZE / secs / 1048576.0 : 0;

   tsdec_log(1, "--- summary ---");
   tsdec_log(1, "packets read       : %lu", s->total_packets);
   tsdec_log(1, "encrypted packets  : %lu", s->encrypted_packets);
   tsdec_log(1, "decrypted packets  : %lu", s->decrypted_packets);
   tsdec_log(1, "copied unencrypted : %lu", s->passthrough_packets);
   if (s->dropped_packets)
      tsdec_log(1, "left still scrambled: %lu", s->dropped_packets);
   tsdec_log(1, "sync / resync      : %lu / %lu", s->sync_count, s->resync_count);
   if (s->corrupt_packets)
      tsdec_log(1, "bad sync byte      : %lu", s->corrupt_packets);
   if (s->checksum_corrections)
      tsdec_log(1, "cw checksums fixed : %lu", s->checksum_corrections);
   if (secs > 0)
      tsdec_log(1, "throughput         : %.1f MiB/s in %.2f s", mbps, secs);
}

/* ------------------------------------------------------------------ *
 * decrypt a transport stream with a control word log
 * ------------------------------------------------------------------ */

/* Walks one block, deciding for every packet whether it is decrypted and with
 * which logged cw. cw_of[i] receives the index into cwl->cws, or -1 when the
 * packet is left alone. Runs on the scout thread and mutates only its own
 * key context. */
static int plan_block (csa_ctx_t *ctx, unsigned char *buf, size_t n,
                       const cwl_t *cwl, int *cw_of, int *synced, int *cur_cw,
                       int *last_parity, const int *pid_filter, int npid_filter,
                       int allow_resync, stats_t *stats)
{
   size_t i;
   int k;

   /* Which pids have been seen to start a PES unit. The resync check is only
    * meaningful on those, because 00 00 01 is the known plaintext of an
    * elementary stream and nothing else: a PUSI packet on a psi pid starts
    * with a pointer field, and a PUSI packet on a scrambled pid is exactly
    * the packet whose payload we are trying to read. 8192 flags is 8 KiB, and
    * it is the whole pid space. */
   static unsigned char pid_has_pes[8192];

   for (i = 0; i < n; i++)
   {
      unsigned char *p = buf + i * PCKTSIZE;
      unsigned char trial[PCKTSIZE];
      int best = -1;

      cw_of[i] = -1;

      if (p[0] != 0x47)
      {
         stats->corrupt_packets++;
         continue;
      }

      if (!IsEncryptedPacket(p))
      {
         stats->passthrough_packets++;
         continue;
      }

      if (!pid_selected(packet_pid(p), pid_filter, npid_filter))
      {
         stats->passthrough_packets++;
         continue;
      }

      stats->encrypted_packets++;

      if (!*synced)
      {
         /* Only a PUSI packet can prove a key: its decrypted payload must
          * start a PES unit. Trying every logged cw here is what makes sync
          * survive a recording that starts before the log does. */
         if (IsPUSIPacket(p))
         {
            int par = GetPacketParity(p) ? 1 : 0;
            for (k = 0; k < cwl->count; k++)
            {
               if (cwl->cws[k].parity != par)
                  continue;
               csa_key_set_ctx(ctx, cwl->cws[k].cw, cwl->cws[k].parity);
               memcpy(trial, p, PCKTSIZE);
               csa_decrypt_ctx(ctx, trial);
               if (packet_has_pes_header(trial))
               {
                  best = k;
                  break;
               }
            }
         }

      if (best < 0)
      {
         stats->dropped_packets++;
         continue;
      }

      *synced = 1;
      *cur_cw = best;
      *last_parity = cwl->cws[best].parity;
      csa_key_set_ctx(ctx, cwl->cws[best].cw, cwl->cws[best].parity);
      /* a pid that just produced a PES start code under some key is one we can
       * check later, which is the only thing that makes the resync test safe */
      pid_has_pes[packet_pid(p)] = 1;
      stats->sync_count++;
      tsdec_log(3, "sync at packet %lu using cw #%d (parity %d)",
                stats->total_packets + i, best, cwl->cws[best].parity);
   }

   /* Past the first sync the logged cw is taken on trust, which is normally
    * right and costs nothing to check. It is not right when the recording was
    * cut somewhere other than a key change, which is the ordinary case for a
    * capture started by hand: from there on every packet decrypts to noise and
    * nothing anywhere says so, because a wrong key produces no error, it just
    * produces rubbish.
    *
    * A transport stream offers a check, but not the obvious one. It is tempting
    * to say that a PUSI packet decrypts to a PES start code, so a PUSI packet
    * that does not proves the key is wrong. That is wrong, and it took a
    * recording with a PAT in it to show it: a PUSI packet on a PSI pid starts
    * with the pointer field of a table section, not with 00 00 01, so every
    * table update would have been read as a lost key and the run shredded.
    *
    * So the check is only made on packets where the known plaintext actually
    * is, which is a pid that has already been seen to start a PES unit. Those
    * are the pids that carry elementary streams, and they carry them for the
    * whole recording, so learning which they are at the first sync is enough.
    * A pid that has never produced a PES start code is left alone, which means
    * a wrong key on a stream we have not validated goes unnoticed. That is the
    * safe way round: missing a resync leaves rubbish, inventing one destroys a
    * decryption that was working. */
   else if (allow_resync && IsPUSIPacket(p) && pid_has_pes[packet_pid(p)])
   {
      int par = GetPacketParity(p) ? 1 : 0;
      int found = -1;

      csa_key_set_ctx(ctx, cwl->cws[*cur_cw].cw,
                      (unsigned char) cwl->cws[*cur_cw].parity);
      memcpy(trial, p, PCKTSIZE);
      csa_decrypt_ctx(ctx, trial);

      if (!packet_has_pes_header(trial))
      {
         for (k = 0; k < cwl->count; k++)
         {
            if (cwl->cws[k].parity != par)
               continue;
            csa_key_set_ctx(ctx, cwl->cws[k].cw, cwl->cws[k].parity);
            memcpy(trial, p, PCKTSIZE);
            csa_decrypt_ctx(ctx, trial);
            if (packet_has_pes_header(trial))
            {
               found = k;
               break;
            }
         }

         /* The pid is known to carry elementary streams, so a payload that
          * starts no unit at all means the key has gone, not that this
          * particular packet is a table or a stray. */
         if (found >= 0 && found != *cur_cw)
         {
            tsdec_log(2, "packet %lu: lost the key, the control word log is "
                      "offset; resuming at cw #%d", stats->total_packets + i,
                      found);
            *cur_cw = found;
            *last_parity = cwl->cws[found].parity;
            csa_key_set_ctx(ctx, cwl->cws[found].cw,
                            (unsigned char) cwl->cws[found].parity);
            stats->resync_count++;
         }
      }
      else
      {
         /* still the right key, and we know this pid carries elementary
          * streams, so remember that for the next check */
         pid_has_pes[packet_pid(p)] = 1;
      }
   }

      {
         int par = GetPacketParity(p) ? 1 : 0;

         /* the plain path: follow the log across a parity change */
         if (par != *last_parity)
         {
            int next = -1;
            for (k = *cur_cw + 1; k < cwl->count; k++)
               if (cwl->cws[k].parity == par)
               {
                  next = k;
                  break;
               }

            if (next < 0)
            {
               tsdec_log(2, "packet %lu: control word log ends before the next "
                         "parity change (need a cw with parity %d)",
                         stats->total_packets + i, par);
               *synced = 0;
               stats->dropped_packets++;
               continue;
            }

            *cur_cw = next;
            *last_parity = par;
            tsdec_log(3, "packet %lu: cw #%d (parity %d)",
                      stats->total_packets + i, next, par);
         }

         cw_of[i] = *cur_cw;
         stats->decrypted_packets++;
      }
   }

   return 0;
}

/* Applies the plan: group the block by parity and run each group through the
 * bitsliced engine in batches. This is the expensive part and is what the
 * worker threads run. */
static void decrypt_block (csa_ctx_t *ctx, unsigned char *buf, size_t n,
                           const cwl_t *cwl, const int *cw_of, int *batch)
{
   int bs = csa_bs_batch_size();
   size_t i;
   int parity;

   for (parity = 0; parity < 2; parity++)
   {
      int key_index = -1;
      int n_in_batch = 0;

      for (i = 0; i < n; i++)
      {
         unsigned char *p = buf + i * PCKTSIZE;

         if (cw_of[i] < 0)
            continue;
         if ((GetPacketParity(p) ? 1 : 0) != parity)
            continue;

         /* a batch is decrypted with one key, so a cw change flushes it */
         if (cw_of[i] != key_index)
         {
            if (n_in_batch)
            {
               csa_key_set_ctx(ctx, cwl->cws[key_index].cw, (unsigned char) parity);
               csa_bs_decrypt_ctx(ctx, buf, batch, n_in_batch, (unsigned char) parity);
               n_in_batch = 0;
            }
            key_index = cw_of[i];
         }

         batch[n_in_batch++] = (int) (i * PCKTSIZE);
         if (n_in_batch == bs)
         {
            csa_key_set_ctx(ctx, cwl->cws[key_index].cw, (unsigned char) parity);
            csa_bs_decrypt_ctx(ctx, buf, batch, n_in_batch, (unsigned char) parity);
            n_in_batch = 0;
         }
      }

      if (n_in_batch)
      {
         csa_key_set_ctx(ctx, cwl->cws[key_index].cw, (unsigned char) parity);
         csa_bs_decrypt_ctx(ctx, buf, batch, n_in_batch, (unsigned char) parity);
      }
   }
}

/* ------------------------------------------------------------------ *
 * parallel decrypt pipeline
 * ------------------------------------------------------------------ *
 *
 * Splitting the work into "plan" and "decrypt" is what makes threads pay off:
 *
 *   scout    one thread reads blocks and decides, for every packet, which
 *            logged control word applies. Past the initial sync this only
 *            inspects packet headers, so it is cheap, and it must stay serial
 *            because each control word depends on the previous one.
 *
 *   workers  N threads take planned blocks, run the bitsliced CSA engine over
 *            them and write them to their fixed offset in the output. The
 *            output position of a block is known as soon as it has been read,
 *            so the writes never need to be ordered or locked.
 *
 * Blocks travel through a small ring of slots, which keeps memory bounded
 * regardless of how large the recording is.
 */

typedef struct
{
   unsigned char *buf;
   int           *cw_of;
   size_t         n;              /* packets in this block */
   unsigned long  index;          /* block number, also its output offset */
   int            ready;          /* planned and waiting for a worker */
   int            busy;           /* a worker is on it */
} block_t;

typedef struct
{
   const char   *ifile;
   const char   *ofile;
   FILE         *out;
   const cwl_t  *cwl;
   int           verbose;
   int           progress;
   const int    *pid_filter;
   int           npid_filter;
   int           allow_resync;
   int           nworkers;

   /* progress reporting, both polled from the scout */
   unsigned long total_packets;    /* 0 when the size is not known upfront */
   unsigned long reported;
   double        last_progress;    /* when the callback last fired */
   int           have_progress_time;
   tsdec_progress_fn on_progress;
   void         *progress_user;

   block_t      *slots;
   int           nslots;

   /* ring cursors and counters, all guarded by mutex */
   tsdec_mutex_t mutex;
   tsdec_cond_t  produced;
   tsdec_cond_t  consumed;
   int           planning;        /* next block index the scout will fill */
   int           claiming;        /* next block index a worker will look at */
   int           completed;       /* blocks finished and written */
   int           outstanding;     /* planned but not yet written */
   int           plan_done;
   int           stop;
   int           error;
   int           canceled;

   stats_t       scout_stats;
   stats_t      *worker_stats;
   csa_ctx_t   **worker_ctx;
} pipeline_t;

typedef struct
{
   pipeline_t *pipeline;
   int         id;
   FILE       *out;                /* per worker: stdio is not thread safe */
} worker_arg_t;

/* Position of block `i` in the ring. */
#define SLOT(pl, i) (&(pl)->slots[(i) % (pl)->nslots])

static int open_output (const char *ofile, FILE **out)
{
   if (strcmp(ofile, "-") == 0)
   {
      *out = stdout;
      return RET_OK;
   }
   *out = fopen(ofile, "wb");
   if (!*out)
   {
      tsdec_log(0, "cannot open output file %s", ofile);
      return RET_OUTFILEOPEN;
   }
   return RET_OK;
}

static int write_block_at (FILE *out, unsigned long block_index,
                           const unsigned char *buf, size_t n)
{
   long long offset = (long long) block_index * (long long) BLOCK_PACKETS * PCKTSIZE;

#if defined(_WIN32)
   if (_fseeki64(out, offset, SEEK_SET) != 0)
      return -1;
#else
   if (fseeko(out, (off_t) offset, SEEK_SET) != 0)
      return -1;
#endif
   return fwrite(buf, PCKTSIZE, n, out) == n ? 0 : -1;
}

static void *worker_main (void *arg)
{
   worker_arg_t *wa = (worker_arg_t *) arg;
   pipeline_t *pl = wa->pipeline;
   int id = wa->id;
   FILE *out = wa->out;
   csa_ctx_t *ctx;
   stats_t *st;
   int *batch;

   /* one key context and one stats struct per worker, so the hot path needs
    * no locking at all */
   ctx = csa_ctx_new();
   st = &pl->worker_stats[id];
   batch = malloc(sizeof(int) * csa_bs_batch_size());
   if (!ctx || !batch)
   {
      pl->error = RET_OUTOFMEMORY;
      free(batch);
      return NULL;
   }
   pl->worker_ctx[id] = ctx;

   for (;;)
   {
      block_t *b = NULL;

      mutex_lock(&pl->mutex);
      for (;;)
      {
         int s;

         if (pl->stop)
            break;

         /* Take any planned block that is not already claimed. Scouting and
          * decryption are independent per block, so there is no reason for a
          * worker to insist on a particular one -- doing that would let a
          * worker block on a block the scout has not reached yet while the
          * scout blocks waiting for that worker. */
         for (s = 0; s < pl->nslots; s++)
         {
            int k = (pl->claiming + s) % pl->nslots;
            if (pl->slots[k].ready && !pl->slots[k].busy)
            {
               pl->slots[k].busy = 1;
               b = &pl->slots[k];
               pl->claiming = (k + 1) % pl->nslots;
               break;
            }
         }
         if (b)
            break;

         if (pl->plan_done && pl->outstanding == 0)
            break;

         cond_wait(&pl->produced, &pl->mutex);
      }
      mutex_unlock(&pl->mutex);

      if (!b)
      {
         break;
      }

      decrypt_block(ctx, b->buf, b->n, pl->cwl, b->cw_of, batch);
      st->decrypted_packets += (unsigned long) b->n;

      if (write_block_at(out, b->index, b->buf, b->n) != 0)
      {
         mutex_lock(&pl->mutex);
         pl->error = RET_OUTFILEOPEN;
         pl->stop = 1;
         cond_broadcast(&pl->produced);
         mutex_unlock(&pl->mutex);
      }

      mutex_lock(&pl->mutex);
      b->ready = 0;
      b->busy = 0;
      pl->outstanding--;
      pl->completed++;
      /* Both condition variables are used on the same ring, so a single
       * broadcast on each keeps the scout (waiting on consumed) and the idle
       * workers (waiting on produced) in step. Signalling only one of them
       * is what strands a worker when the last block is handed out. */
      cond_broadcast(&pl->consumed);
      cond_broadcast(&pl->produced);
      mutex_unlock(&pl->mutex);
   }

   free(batch);
   return NULL;
}

/* Single threaded decrypt. Kept as the fallback when threads are unavailable
 * or the caller asked for one worker. */
static int decrypt_serial (const char *ifile, FILE *out, const cwl_t *cwl,
                           int verbose, int progress, const int *pid_filter,
                           int npid_filter, int allow_resync, stats_t *stats,
                           tsdec_progress_fn on_progress, void *progress_user)
{
   reader_t r;
   csa_ctx_t *ctx;
   int *cw_of, *batch;
   int ret, synced = 0, cur_cw = -1, last_parity = -1;
   unsigned long reported = 0;
   unsigned long total_packets = 0;
   double last_progress = 0;
   int have_progress_time = 0;
   size_t n;
   int i;

   ret = reader_open(&r, ifile, BLOCK_PACKETS);
   if (ret != RET_OK)
      return ret;

   total_packets = reader_packet_count(ifile);

   ctx = csa_ctx_new();
   cw_of = malloc(sizeof(int) * BLOCK_PACKETS);
   batch = malloc(sizeof(int) * csa_bs_batch_size());
   if (!ctx || !cw_of || !batch)
   {
      csa_ctx_free(ctx);
      free(cw_of);
      free(batch);
      reader_close(&r);
      return RET_OUTOFMEMORY;
   }

   for (i = 0; i < cwl->count; i++)
      csa_key_set_ctx(ctx, cwl->cws[i].cw, cwl->cws[i].parity);

   tsdec_log(2, "trying to sync...");

   while ((n = reader_fill(&r)) > 0)
   {
      if (tsdec_cancel_requested())
      {
         stats->canceled = 1;
         ret = RET_CANCELED;
         goto serial_done;
      }

      plan_block(ctx, r.buf, n, cwl, cw_of, &synced, &cur_cw, &last_parity,
                 pid_filter, npid_filter, allow_resync, stats);
      decrypt_block(ctx, r.buf, n, cwl, cw_of, batch);

      if (fwrite(r.buf, PCKTSIZE, n, out) != n)
      {
         tsdec_log(0, "write error");
         ret = RET_OUTFILEOPEN;
         goto serial_done;
      }

      stats->total_packets += (unsigned long) n;

      if (on_progress)
      {
         /* rate limited by time, see the note in scout_main */
         double now = now_seconds();
         if (!have_progress_time)
         {
            have_progress_time = 1;
            last_progress = now;
         }
         if (now - last_progress >= 0.1)
         {
            last_progress = now;
            on_progress(progress_user, stats->total_packets, total_packets,
                        stats);
         }
      }
      else if (progress && stats->total_packets - reported >= 500000)
      {
         reported = stats->total_packets;
         tsdec_log(1, "... %lu packets (%.1f MiB)", stats->total_packets,
                   stats->total_packets * PCKTSIZE / 1048576.0);
      }
   }
   ret = RET_OK;

serial_done:
   (void) verbose;
   csa_ctx_free(ctx);
   free(cw_of);
   free(batch);
   reader_close(&r);
   return ret;
}

/* Scout: reads blocks, plans them, hands them to the ring. */
static void scout_main (pipeline_t *pl)
{
   reader_t r;
   csa_ctx_t *ctx;
   int synced = 0, cur_cw = -1, last_parity = -1;
   unsigned long reported = 0;
   int index = 0;
   int i;

   if (reader_open(&r, pl->ifile, BLOCK_PACKETS) != RET_OK)
   {
      mutex_lock(&pl->mutex);
      pl->error = RET_INFILE_NOTOPEN;
      pl->plan_done = 1;
      cond_broadcast(&pl->produced);
      mutex_unlock(&pl->mutex);
      return;
   }

   ctx = csa_ctx_new();
   if (ctx)
      for (i = 0; i < pl->cwl->count; i++)
         csa_key_set_ctx(ctx, pl->cwl->cws[i].cw, pl->cwl->cws[i].parity);

   tsdec_log(2, "trying to sync...");

   for (;;)
   {
      block_t *b;
      size_t n;
      int stop = 0;

      /* A stop request stops the scout from planning anything further, but the
       * blocks already in the ring still have to be decrypted and written:
       * dropping them would cut the output at an arbitrary packet and lose
       * whatever was decoded but not yet flushed. So plan_done is raised and
       * the workers drain, rather than setting stop and abandoning the ring. */
      if (tsdec_cancel_requested())
      {
         mutex_lock(&pl->mutex);
         pl->canceled = 1;
         pl->plan_done = 1;
         cond_broadcast(&pl->produced);
         cond_broadcast(&pl->consumed);
         mutex_unlock(&pl->mutex);
         break;
      }

      /* wait until the slot we want has been freed by the workers */
      mutex_lock(&pl->mutex);
      while (pl->slots[index % pl->nslots].ready && !pl->stop
             && !pl->canceled)
         cond_wait(&pl->consumed, &pl->mutex);
      stop = pl->stop || pl->canceled;
      mutex_unlock(&pl->mutex);

      if (stop)
         break;

      n = reader_fill(&r);
      if (n == 0)
      {
         mutex_lock(&pl->mutex);
         pl->plan_done = 1;
         cond_broadcast(&pl->produced);
         mutex_unlock(&pl->mutex);
         break;
      }

      b = SLOT(pl, index);
      memcpy(b->buf, r.buf, n * PCKTSIZE);

      plan_block(ctx, b->buf, n, pl->cwl, b->cw_of, &synced, &cur_cw,
                 &last_parity, pl->pid_filter, pl->npid_filter,
                 pl->allow_resync, &pl->scout_stats);
      pl->scout_stats.total_packets += (unsigned long) n;

      mutex_lock(&pl->mutex);
      b->n = n;
      b->index = (unsigned long) index;
      b->ready = 1;
      pl->planning = index + 1;
      pl->outstanding++;
      cond_broadcast(&pl->produced);
      cond_broadcast(&pl->consumed);
      mutex_unlock(&pl->mutex);

      if (pl->on_progress)
      {
         unsigned long done = pl->scout_stats.total_packets;
         /* Rate limit by elapsed time, not by packet count: a count threshold
          * means a small recording reports nothing until the very end, while
          * a time threshold keeps the bar moving whatever the file size. The
          * callback may be doing something as costly as touching a socket, so
          * cap it at about ten times a second. */
         double now = now_seconds();
         if (!pl->have_progress_time)
         {
            pl->have_progress_time = 1;
            pl->last_progress = now;
         }
         if (now - pl->last_progress >= 0.1)
         {
            pl->last_progress = now;
            pl->reported = done;
            pl->on_progress(pl->progress_user, done, pl->total_packets,
                            &pl->scout_stats);
         }
      }
      else if (pl->progress && pl->scout_stats.total_packets - reported >= 500000)
      {
         reported = pl->scout_stats.total_packets;
         tsdec_log(1, "... %lu packets (%.1f MiB)", reported,
                   reported * PCKTSIZE / 1048576.0);
      }

      index++;
   }

   csa_ctx_free(ctx);
   reader_close(&r);

   mutex_lock(&pl->mutex);
   pl->plan_done = 1;
   cond_broadcast(&pl->produced);
   mutex_unlock(&pl->mutex);
}

static int decrypt_parallel (const char *ifile, const char *ofile,
                             const cwl_t *cwl, int nworkers, int verbose,
                             int progress, const int *pid_filter,
                             int npid_filter, int allow_resync, stats_t *stats,
                             tsdec_progress_fn on_progress, void *progress_user)
{
   pipeline_t pl;
   tsdec_thread_t *threads = NULL;
   worker_arg_t *wargs = NULL;
   int i, ret = RET_OK;

   memset(&pl, 0, sizeof(pl));
   pl.ifile = ifile;
   pl.ofile = ofile;
   pl.cwl = cwl;
   pl.verbose = verbose;
   pl.progress = progress;
   pl.pid_filter = pid_filter;
   pl.npid_filter = npid_filter;
   pl.allow_resync = allow_resync;
   pl.nworkers = nworkers;
   pl.on_progress = on_progress;
   pl.progress_user = progress_user;
   pl.total_packets = reader_packet_count(ifile);

   ret = open_output(ofile, &pl.out);
   if (ret != RET_OK)
      return ret;

   /* enough slots to keep every worker fed without unbounded memory */
   pl.nslots = nworkers * 3 + 2;
   if (pl.nslots < 4)
      pl.nslots = 4;

   pl.slots = calloc((size_t) pl.nslots, sizeof(block_t));
   threads = calloc((size_t) nworkers, sizeof(tsdec_thread_t));
   wargs = calloc((size_t) nworkers, sizeof(worker_arg_t));
   pl.worker_stats = calloc((size_t) nworkers, sizeof(stats_t));
   pl.worker_ctx = calloc((size_t) nworkers, sizeof(csa_ctx_t *));

   if (!pl.slots || !threads || !wargs || !pl.worker_stats || !pl.worker_ctx)
      ret = RET_OUTOFMEMORY;

   for (i = 0; ret == RET_OK && i < pl.nslots; i++)
   {
      pl.slots[i].buf = malloc((size_t) BLOCK_PACKETS * PCKTSIZE);
      pl.slots[i].cw_of = malloc(sizeof(int) * BLOCK_PACKETS);
      if (!pl.slots[i].buf || !pl.slots[i].cw_of)
      {
         ret = RET_OUTOFMEMORY;
         break;
      }
   }

   if (ret == RET_OK)
   {
      mutex_init(&pl.mutex);
      cond_init(&pl.produced);
      cond_init(&pl.consumed);
   }

   for (i = 0; ret == RET_OK && i < nworkers; i++)
   {
      wargs[i].pipeline = &pl;
      wargs[i].id = i;
      /* stdio FILE objects are not thread safe and every worker seeks and
       * writes independently, so give each one its own handle on the same
       * file. stdout cannot be reopened, so fall back to a single worker. */
      if (pl.out == stdout)
      {
         if (i > 0)
         {
            ret = RET_BATCH;
            break;
         }
         wargs[i].out = pl.out;
      }
      else
      {
         /* pl.out already created (or opened) the file on the first pass */
         wargs[i].out = fopen(ofile, "r+b");
         if (!wargs[i].out)
         {
            tsdec_log(0, "worker %d cannot open %s", i, ofile);
            ret = RET_OUTFILEOPEN;
            break;
         }
      }

      if (tsdec_thread_start(&threads[i], worker_main, &wargs[i]) != 0)
      {
         ret = RET_OUTOFMEMORY;
         break;
      }
      pl.nworkers = i + 1;         /* only count threads that really started */
   }

   if (ret == RET_OK)
      scout_main(&pl);

   mutex_lock(&pl.mutex);
   pl.plan_done = 1;
   cond_broadcast(&pl.produced);
   mutex_unlock(&pl.mutex);

   for (i = 0; i < pl.nworkers; i++)
      tsdec_thread_join(threads[i]);

   /* close the per worker handles before reporting the result */
   for (i = 0; i < nworkers; i++)
      if (wargs[i].out && wargs[i].out != pl.out && wargs[i].out != stdout)
         fclose(wargs[i].out);

   if (pl.error)
      ret = pl.error;

   if (pl.out)
   {
      fflush(pl.out);
      if (pl.out != stdout)
         fclose(pl.out);
   }

   /* merge worker counters into the caller's stats */
   for (i = 0; i < pl.nworkers; i++)
   {
      stats->decrypted_packets += pl.worker_stats[i].decrypted_packets;
      csa_ctx_free(pl.worker_ctx[i]);
   }
   stats->total_packets = pl.scout_stats.total_packets;
   stats->encrypted_packets = pl.scout_stats.encrypted_packets;
   stats->passthrough_packets = pl.scout_stats.passthrough_packets;
   stats->sync_count = pl.scout_stats.sync_count;
   stats->corrupt_packets = pl.scout_stats.corrupt_packets;
   stats->dropped_packets = pl.scout_stats.dropped_packets;
   /* resync is counted by the scout as it happens, not derived from the sync
    * count: losing and regaining the key somewhere in the middle is one
    * resync and no new sync, which is exactly what used to go unreported */
   stats->resync_count = pl.scout_stats.resync_count;
   stats->canceled = pl.canceled;
   if (pl.canceled && ret == RET_OK)
      ret = RET_CANCELED;


   for (i = 0; i < pl.nslots; i++)
   {
      free(pl.slots[i].buf);
      free(pl.slots[i].cw_of);
   }
   free(pl.slots);
   free(threads);
   free(wargs);
   free(pl.worker_stats);
   free(pl.worker_ctx);
   return ret;
}

int tsdec_run (const tsdec_job_t *job, stats_t *stats)
{
   int ret;
   double t0, t1;

   memset(stats, 0, sizeof(*stats));

   if (job->cw_blocker > 0)
      tsdec_log(3, "cw change blocker set to %d packets", job->cw_blocker);

   t0 = now_seconds();

   if (job->nworkers > 1)
   {
      tsdec_log(3, "decrypting with %d worker threads", job->nworkers);
      ret = decrypt_parallel(job->ifile, job->ofile, job->cwl, job->nworkers,
                             job->verbose, job->progress, job->pid_filter,
                             job->npid_filter, job->allow_resync, stats,
                             job->on_progress, job->progress_user);
   }
   else
   {
      FILE *out;
      ret = open_output(job->ofile, &out);
      if (ret == RET_OK)
      {
         ret = decrypt_serial(job->ifile, out, job->cwl, job->verbose,
                              job->progress, job->pid_filter,
                              job->npid_filter, job->allow_resync, stats,
                              job->on_progress, job->progress_user);
         fflush(out);
         if (out != stdout)
            fclose(out);
      }
   }

   t1 = now_seconds();

   if (job->verbose >= 1)
      report_stats(stats, t1 - t0);

   if (ret == RET_CANCELED)
   {
      tsdec_log(1, "stopped on request after %lu packets (%.1f MiB); the "
                "partial output is left in place",
                stats->total_packets,
                stats->total_packets * PCKTSIZE / 1048576.0);
      return ret;
   }
   if (ret == RET_OK && stats->encrypted_packets && stats->sync_count == 0)
   {
      tsdec_log(2, "could not sync the control word log to this recording");
      ret = RET_NOSYNC;
   }
   else if (ret == RET_OK && stats->encrypted_packets == 0)
   {
      tsdec_log(2, "input stream contains no encrypted packets");
      ret = RET_NOTCRYPTED;
   }

   if (stats->resync_count)
      tsdec_log(1, "resynced %lu time(s): the control word log does not line "
                "up with the whole recording", stats->resync_count);

   return ret;
}

void tsdec_job_init (tsdec_job_t *job)
{
   memset(job, 0, sizeof(*job));
   job->cw_blocker = 300;
   job->verbose = 2;
   job->nworkers = 0;              /* 0 means "work it out at run time" */
}

int decrypt_cwl_file (const char *ifile, const char *ofile, const cwl_t *cwl,
                      int cw_blocker, int verbose, int progress,
                      const int *pid_filter, int npid_filter,
                      int allow_resync, int nworkers, stats_t *stats)
{
   tsdec_job_t job;

   tsdec_job_init(&job);
   job.ifile = ifile;
   job.ofile = ofile;
   job.cwl = cwl;
   job.cw_blocker = cw_blocker;
   job.verbose = verbose;
   job.progress = progress;
   job.pid_filter = pid_filter;
   job.npid_filter = npid_filter;
   job.allow_resync = allow_resync;
   job.nworkers = nworkers;

   return tsdec_run(&job, stats);
}

int tsdec_default_workers (void)
{
   int n = tsdec_cpu_count();
   return n > 1 ? n : 1;
}

/* ------------------------------------------------------------------ *
 * analyze
 * ------------------------------------------------------------------ */

#define MAX_PIDS 512

typedef struct
{
   int            pid;
   unsigned long  count;
   unsigned long  scrambled;
   unsigned long  cc_errors;
   unsigned char  last_cc;
   int            have_cc;
} pidstat_t;

int analyze_file (const char *ifile, int verbose, const int *pid_filter,
                  int npid_filter, stats_t *stats)
{
   reader_t r;
   pidstat_t *pid = calloc(MAX_PIDS, sizeof(pidstat_t));
   size_t n, i;
   int npid = 0, ret, k;

   memset(stats, 0, sizeof(*stats));
   if (!pid)
      return RET_OUTOFMEMORY;

   ret = reader_open(&r, ifile, BLOCK_PACKETS);
   if (ret != RET_OK)
   {
      free(pid);
      return ret;
   }

   while ((n = reader_fill(&r)) > 0)
   {
      if (tsdec_cancel_requested())
      {
         stats->canceled = 1;
         ret = RET_CANCELED;
         goto analyze_done;
      }

      for (i = 0; i < n; i++)
      {
         unsigned char *p = r.buf + i * PCKTSIZE;
         unsigned long cc;
         int this_pid;

         stats->total_packets++;
         if (p[0] != 0x47)
         {
            stats->corrupt_packets++;
            continue;
         }

         this_pid = packet_pid(p);
         cc = p[3] & 0x0F;

         for (k = 0; k < npid; k++)
            if (pid[k].pid == this_pid)
               break;
         if (k == npid)
         {
            if (npid >= MAX_PIDS)
               continue;
            pid[npid].pid = this_pid;
            npid++;
         }

         if (pid[k].have_cc &&
             ((cc - pid[k].last_cc) & 0x0F) != 1 &&
             !(p[5] & 0x80))          /* discontinuity indicator set: fine */
            pid[k].cc_errors++;

         pid[k].last_cc = (unsigned char) cc;
         pid[k].have_cc = 1;
         pid[k].count++;

         if (IsEncryptedPacket(p))
         {
            pid[k].scrambled++;
            stats->encrypted_packets++;
         }
      }
   }

analyze_done:
   tsdec_log(1, "pid survey for %s", ifile);
   tsdec_log(1, "%-7s %12s %12s %7s %9s", "pid", "packets", "scrambled", "share", "cc errors");
   for (k = 0; k < npid; k++)
   {
      if (!pid_selected(pid[k].pid, pid_filter, npid_filter))
         continue;
      tsdec_log(1, "0x%04x  %12lu %12lu %6.1f%% %9lu",
                pid[k].pid, pid[k].count, pid[k].scrambled,
                stats->total_packets ? 100.0 * pid[k].count / stats->total_packets : 0.0,
                pid[k].cc_errors);
   }
   tsdec_log(1, "%lu packets total, %lu scrambled, %lu without a sync byte",
             stats->total_packets, stats->encrypted_packets, stats->corrupt_packets);

   free(pid);
   reader_close(&r);
   (void) verbose;
   return ret;
}

/* ------------------------------------------------------------------ *
 * constant control word
 * ------------------------------------------------------------------ */

int ccw_file (const char *ifile, const char *ofile, const unsigned char *ccw,
              int encrypt, int verbose, stats_t *stats)
{
   reader_t r;
   FILE *out;
   size_t n, i;
   int ret;

   memset(stats, 0, sizeof(*stats));

   csa_key_set(ccw, 0);
   csa_key_set(ccw + 8, 1);

   ret = reader_open(&r, ifile, BLOCK_PACKETS);
   if (ret != RET_OK)
      return ret;

   if (strcmp(ofile, "-") == 0)
      out = stdout;
   else if (!(out = fopen(ofile, "wb")))
   {
      reader_close(&r);
      return RET_OUTFILEOPEN;
   }

   while ((n = reader_fill(&r)) > 0)
   {
      for (i = 0; i < n; i++)
      {
         unsigned char *p = r.buf + i * PCKTSIZE;
         stats->total_packets++;
         if (p[0] != 0x47)
         {
            stats->corrupt_packets++;
            continue;
         }
         if (encrypt)
            csa_encrypt(p, GetPacketParity(p) ? 1 : 0);
         else
            csa_decrypt(p);
         stats->encrypted_packets++;
      }

      if (fwrite(r.buf, PCKTSIZE, n, out) != n)
      {
         tsdec_log(0, "write error on %s", ofile);
         if (out != stdout)
            fclose(out);
         else
            fflush(out);
         reader_close(&r);
         return RET_OUTFILEOPEN;
      }
   }

   if (out != stdout)
      fclose(out);
   else
      fflush(out);

   reader_close(&r);
   (void) verbose;
   return RET_OK;
}

/* ------------------------------------------------------------------ *
 * CSA engine self test
 * ------------------------------------------------------------------ */

#include "csa_testcases.h"

static int csa_case_ok (const unsigned char *key, unsigned char par,
                        const unsigned char *enc, const unsigned char *exp)
{
   unsigned char buf[PCKTSIZE];
   int i;

   csa_key_set(key, par);
   memcpy(buf, enc, PCKTSIZE);
   csa_decrypt(buf);

   for (i = 0; i < PCKTSIZE; i++)
   {
      if (i == 3)
         continue;             /* the scrambling bits are cleared on purpose */
      if (buf[i] != exp[i])
         return 0;
   }
   return 1;
}

int csa_selftest (void)
{
   struct
   {
      unsigned char     par;
      const unsigned char *key;
      const unsigned char *enc;
      const unsigned char *exp;
   } cases[] = {
      { 1, test_1_key,      test_1_encrypted,      test_1_expected },
      { 0, test_2_key,      test_2_encrypted,      test_2_expected },
      { 0, test_3_key,      test_3_encrypted,      test_3_expected },
      { 0, test_p_10_0_key, test_p_10_0_encrypted, test_p_10_0_expected },
      { 0, test_p_1_6_key,  test_p_1_6_encrypted,  test_p_1_6_expected },
      { 0, test_7_key,      test_7_encrypted,      test_7_expected },
   };
   size_t i;

   for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
   {
      if (!csa_case_ok(cases[i].key, cases[i].par,
                       cases[i].enc, cases[i].exp))
      {
         tsdec_log(2, "CSA self test FAILED on vector %u", (unsigned) i);
         return RET_SELFTESTFAILED;
      }
      tsdec_log(4, "CSA self test passed on vector %u", (unsigned) i);
   }
   return RET_OK;
}
