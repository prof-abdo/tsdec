/* TSDEC command line front end. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "tsdec.h"
#include "csa.h"

static void usage (const char *err)
{
   if (err)
      fprintf(stderr, "TSDEC: %s\n\n", err);

   fprintf(stderr,
"TSDEC %s - offline decrypter for recorded DVB transport streams\n"
"\n"
"usage:\n"
"  tsdec -f <cwl> -i <in.ts> [-o <out.ts>] [options]\n"
"  tsdec -a -i <in.ts> [options]\n"
"  tsdec (-e|-d) <ccw> -i <in.ts> -o <out.ts>\n"
"\n"
"decryption:\n"
"  -f <file>     control word log (.cwl) used to decrypt the recording\n"
"  -i <file>     encrypted transport stream to read\n"
"  -o <file>     where to write the result; '-' means stdout\n"
"  -e <ccw>      encrypt with a constant control word and write it out\n"
"  -d <ccw>      decrypt with a constant control word (e.g. BISS)\n"
"                ccw is 16 hex bytes: \"EE EE ... EE OO OO ... OO\"\n"
"\n"
"selection:\n"
"  -p <pid>[,<pid>...]  only act on these PIDs (decimal or 0x hex)\n"
"                        useful when a transponder carries several services\n"
"  -n <count>            number of PIDs to expect after -p\n"
"\n"
"tuning:\n"
"  -t <n>       decrypt with n worker threads (1 disables threading)\n"
"                default: one per cpu\n"
"  -b <n>       ignore a parity change that lasts fewer than n packets\n"
"                (0 disables, default 300)\n"
"  -r           resync past packets with a missing 0x47 sync byte\n"
"  -k           do not repair control word checksums, fail instead\n"
"\n"
"output:\n"
"  -v <n>       verbosity 0..9, higher is chattier (default 2)\n"
"  -q           quiet, same as -v 0\n"
"  -P           show progress while decrypting\n"
"  -h           this help\n"
"\n"
"examples:\n"
"  tsdec -f log.cwl -i recording.ts -o clear.ts -P\n"
"  tsdec -a -i recording.ts\n"
"  tsdec -f log.cwl -i rec.ts -o - | vlc -\n"
"  tsdec -p 0x100,0x101 -f log.cwl -i rec.ts -o clear.ts\n",
      TSDEC_VERSION);
}

static int parse_pid_list (const char *arg, int *out, int max)
{
   char buf[512];
   char *tok;
   int n = 0;

   if (!arg || strlen(arg) >= sizeof(buf))
      return -1;
   strcpy(buf, arg);

   /* strtok_r is POSIX and absent from the Windows CRT, so keep a tiny
    * re-entrant splitter instead of pulling in a portability shim. */
   for (tok = strtok(buf, ",;"); tok; tok = strtok(NULL, ",;"))
   {
      char *end;
      long v;

      while (*tok && isspace((unsigned char) *tok)) tok++;
      if (!*tok)
         continue;
      if (n >= max)
         return -1;

      v = strtol(tok, &end, 0);
      if (end == tok || v < 0 || v > 0x1FFF)
         return -1;
      out[n++] = (int) v;
   }
   return n;
}

/* Accepts both "11 22 33 ..." and "1122334455667788 99aabbccddeeff00". */
static int parse_ccw (const char *arg, unsigned char out[16])
{
   unsigned int v[16];
   int got, i;
   char compact[40] = "";
   size_t len;

   memset(v, 0, sizeof(v));
   memset(out, 0, 16);

   got = sscanf(arg, "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
                &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7],
                &v[8], &v[9], &v[10], &v[11], &v[12], &v[13], &v[14], &v[15]);
   if (got == 16)
   {
      for (i = 0; i < 16; i++)
         out[i] = (unsigned char) v[i];
      return 0;
   }

   /* compact form: two 16 hex digit groups */
   {
      char tmp[80] = "";
      char *p;
      int count = 0;

      if (sscanf(arg, "%79s", tmp) != 1)
         return -1;
      len = strlen(tmp);
      if (len > sizeof(compact) - 1)
         return -1;
      for (p = tmp; *p; p++)
      {
         if (!isxdigit((unsigned char) *p))
            return -1;
         compact[count++] = *p;
      }
      compact[count] = 0;

      if (count == 32)
      {
         for (i = 0; i < 16; i++)
         {
            unsigned int b;
            if (sscanf(compact + i * 2, "%2x", &b) != 1)
               return -1;
            out[i] = (unsigned char) b;
         }
         return 0;
      }
   }

   return -1;
}

static void check_ccw_checksums (const unsigned char *ccw)
{
   int half;

   for (half = 0; half < 2; half++)
   {
      const unsigned char *c = ccw + half * 8;
      unsigned char want0 = (unsigned char) (c[0] + c[1] + c[2]);
      unsigned char want1 = (unsigned char) (c[4] + c[5] + c[6]);
      if (c[3] != want0 || c[7] != want1)
         tsdec_log(2, "control word half %d has a bad checksum "
                   "(%02X%02X%02X%02X %02X%02X%02X%02X, expected "
                   "%02X%02X%02X%02X %02X%02X%02X%02X)",
                   half, c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
                   c[0], c[1], c[2], want0, c[4], c[5], c[6], want1);
   }
}

int main (int argc, char **argv)
{
   const char *ifile = NULL, *ofile = NULL, *cwfile = NULL, *ccwarg = NULL;
   const char *pidarg = NULL;
   int cw_blocker = 300;
   int verbose = 2;
   int progress = 0;
   int analyze = 0;
   int encrypt_ccw = 0;
   int resync = 0;
   int fix_checksums = 1;
   int nworkers = 0;                 /* 0 = pick from cpu count */
   int pid_filter[128];
   int npid_filter = 0;
   int i, ret;
   stats_t stats;
   unsigned char ccw[16];
   cwl_t cwl;

   memset(&cwl, 0, sizeof(cwl));

   for (i = 1; i < argc; i++)
   {
      const char *a = argv[i];
      char opt;
      const char *val;

      if (a[0] != '-' || a[1] == 0)
      {
         fprintf(stderr, "TSDEC: unexpected argument \"%s\"\n", a);
         usage(NULL);
         return RET_USAGE;
      }

      opt = a[1];
      val = a[2] ? a + 2 : NULL;

      if (opt == 'h' || opt == '?')
      {
         usage(NULL);
         return RET_OK;
      }

      if (!val && opt != 'a' && opt != 'r' && opt != 'k' &&
          opt != 'q' && opt != 'P')
      {
         if (i + 1 >= argc)
         {
            fprintf(stderr, "TSDEC: option -%c needs a value\n", opt);
            usage(NULL);
            return RET_USAGE;
         }
         val = argv[++i];
      }

      switch (opt)
      {
         case 'f': cwfile = val; break;
         case 'i': ifile = val; break;
         case 'o': ofile = val; break;
         case 'p': pidarg = val; break;
         case 'e': encrypt_ccw = 1; ccwarg = val; break;
         case 'd': ccwarg = val; break;
         case 'b':
            cw_blocker = atoi(val);
            if (cw_blocker < 0) cw_blocker = 0;
            break;
         case 't':
            nworkers = atoi(val);
            if (nworkers < 1) nworkers = 1;
            break;
         case 'v': verbose = atoi(val); break;
         case 'n': break;               /* accepted for compatibility */
         case 'a': analyze = 1; break;
         case 'r': resync = 1; break;
         case 'k': fix_checksums = 0; break;
         case 'q': verbose = 0; break;
         case 'P': progress = 1; break;
         default:
            fprintf(stderr, "TSDEC: unknown option -%c\n", opt);
            usage(NULL);
            return RET_USAGE;
      }
   }

   if (verbose < 0) verbose = 0;
   if (verbose > 9) verbose = 9;
   g_verbose = verbose;

   if (nworkers == 0)
      nworkers = tsdec_default_workers();

   if (!ifile)
   {
      usage("an input file is required (-i)");
      return RET_USAGE;
   }

   if (pidarg)
   {
      npid_filter = parse_pid_list(pidarg, pid_filter,
                                   (int) (sizeof(pid_filter) / sizeof(pid_filter[0])));
      if (npid_filter < 0)
      {
         fprintf(stderr, "TSDEC: cannot parse pid list \"%s\"\n", pidarg);
         return RET_USAGE;
      }
   }

   /* Ctrl+C should ask the job to stop rather than kill it mid write, so the
    * output stays a whole number of packets and stays playable up to that
    * point. Install it before the self test so even that path can be
    * interrupted on a machine where it somehow hangs. */
   tsdec_install_sigint_handler();
   tsdec_clear_cancel();

   /* the CSA engine can silently produce garbage if it miscompiles, so prove
    * it against the published test vectors before touching any data */
   if ((ret = csa_selftest()) != RET_OK)
   {
      fprintf(stderr, "TSDEC: CSA engine self test failed, refusing to run\n");
      return ret;
   }

   if (analyze)
   {
      ret = analyze_file(ifile, verbose, pid_filter, npid_filter, &stats);
      return ret;
   }

   if (ccwarg)
   {
      if (parse_ccw(ccwarg, ccw) != 0)
      {
         fprintf(stderr, "TSDEC: cannot parse the constant control word\n");
         usage(NULL);
         return RET_USAGE;
      }
      check_ccw_checksums(ccw);

      if (!ofile)
      {
         usage("an output file is required (-o)");
         return RET_USAGE;
      }

      ret = ccw_file(ifile, ofile, ccw, encrypt_ccw, verbose, &stats);
      tsdec_log(2, "%s complete: %lu packets, %.1f MiB",
                encrypt_ccw ? "encrypt" : "decrypt",
                stats.total_packets,
                stats.total_packets * PCKTSIZE / 1048576.0);
      return ret;
   }

   if (!cwfile)
   {
      usage("a control word log is required (-f)");
      return RET_USAGE;
   }
   if (!ofile)
      ofile = NULL;             /* analysed below */

   ret = cwl_load(cwfile, &cwl, fix_checksums, verbose);
   if (ret != RET_OK)
   {
      cwl_free(&cwl);
      return ret;
   }

   if (!ofile)
   {
      fprintf(stderr, "TSDEC: an output file is required (-o, or - for stdout)\n");
      cwl_free(&cwl);
      return RET_USAGE;
   }

   ret = decrypt_cwl_file(ifile, ofile, &cwl, cw_blocker, verbose, progress,
                          pid_filter, npid_filter, resync, nworkers, &stats);

   cwl_free(&cwl);
   return ret;
}
