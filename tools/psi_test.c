/* Program table test.
 *
 * Reading the pat and the pmt is what turns a recording of a whole transponder
 * into something a person can act on, so this checks that the tables are read
 * and that what comes out of them is right: the pids, the pcr, and whether a
 * service is encrypted.
 *
 * A recording with two programs is the case that matters. That is what a
 * satellite transponder normally carries, each service with its own control
 * words, and it is the case that used to be impossible to handle: without
 * knowing which pids belong to which program there is no way to pick one, and
 * the control words of the two are interleaved.
 *
 * The file is built by tools/mk_multi_ts.py, which also writes the cwl log the
 * recording is encrypted against, so the decryption is real rather than a
 * table read on its own. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tsdec.h"

static int bad = 0;

static void check (const char *name, int cond, const char *detail)
{
   if (cond)
   {
      printf ("  PASS  %s\n", name);
   }
   else
   {
      printf ("  FAIL  %s  [%s]\n", name, detail ? detail : "");
      bad++;
   }
}

int main (int argc, char **argv)
{
   const char *ts = argc > 1 ? argv[1] : "test/multi.ts";
   const char *cwl = argc > 2 ? argv[2] : "test/multi.enc.cwl";
   programs_t progs;
   int n, i, j, pids[32], np;

   n = programs_read(ts, &progs, 1);
   check("the recording has program tables", n > 0, "none found");
   if (n <= 0)
   {
      printf ("  psi: FAIL\n");
      return 1;
   }

   check("both services are found", n == 2, "found a different number");

   /* program 1: video on 0x100, audio on 0x101 */
   for (i = 0; i < progs.nprograms; i++)
      if (progs.programs[i].program == 1)
         break;
   check("program 1 is listed", i < progs.nprograms, "missing");
   if (i < progs.nprograms)
   {
      program_t *p = &progs.programs[i];
      char detail[128];

      snprintf(detail, sizeof(detail), "pmt 0x%04x, %d streams",
               p->pmt_pid, p->nstreams);
      check("program 1 has its pmt pid", p->pmt_pid == 0x0050, detail);
      check("program 1 has its pcr pid", p->pcr_pid == 0x0100, detail);
      check("program 1 lists two streams", p->nstreams == 2, detail);

      if (p->nstreams == 2)
      {
         snprintf(detail, sizeof(detail), "0x%04x and 0x%04x",
                  p->streams[0].pid, p->streams[1].pid);
         check("program 1 video is 0x100", p->streams[0].pid == 0x0100, detail);
         check("program 1 audio is 0x101", p->streams[1].pid == 0x0101, detail);
         check("the video is named as such",
               strstr(p->streams[0].name, "mpeg-2") != NULL, p->streams[0].name);
      }
   }

   /* program 2: video on 0x200, no audio */
   for (i = 0; i < progs.nprograms; i++)
      if (progs.programs[i].program == 2)
         break;
   check("program 2 is listed", i < progs.nprograms, "missing");
   if (i < progs.nprograms)
   {
      program_t *p = &progs.programs[i];
      char detail[128];

      snprintf(detail, sizeof(detail), "pmt 0x%04x, %d streams",
               p->pmt_pid, p->nstreams);
      check("program 2 has its own pmt pid", p->pmt_pid == 0x0060, detail);
      check("program 2 has one stream", p->nstreams == 1, detail);
      if (p->nstreams == 1)
      {
         snprintf(detail, sizeof(detail), "0x%04x", p->streams[0].pid);
         check("program 2 video is 0x200", p->streams[0].pid == 0x0200, detail);
      }
   }

   /* the two services must not share pids, or picking one is meaningless */
   {
      int a[8], na = programs_pids(&progs, 1, a, 8);
      int b[8], nb = programs_pids(&progs, 2, b, 8);
      int overlap = 0;

      check("program 1 resolves to two pids", na == 2, "wrong count");
      check("program 2 resolves to one pid", nb == 1, "wrong count");
      for (i = 0; i < na; i++)
         for (j = 0; j < nb; j++)
            if (a[i] == b[j])
               overlap++;
      check("the two services share no pids", overlap == 0, "they overlap");
   }

   /* every pid, which is what a whole transponder decrypt needs */
   np = programs_pids(&progs, -1, pids, 32);
   check("all pids together are three", np == 3, "wrong count");

   /* and a program that is not there must be reported rather than guessed */
   np = programs_pids(&progs, 99, pids, 32);
   check("an absent program resolves to nothing", np == 0, "it invented pids");

   /* a file with no tables at all is a bare elementary stream, not an error */
   {
      programs_t none;
      FILE *f = fopen("test/nots.bin", "rb");
      if (f)
      {
         fclose(f);
         check("a file that is not a transport stream reads no programs",
               programs_read("test/nots.bin", &none, 1) == 0, "read some");
      }
   }

   /* decrypting one program of a two program recording has to leave the other
    * alone, which is the whole point of reading the tables */
   {
      cwl_t log;
      stats_t st;
      char detail[128];

      if (cwl_load(cwl, &log, 1, 0) == RET_OK)
      {
         np = programs_pids(&progs, 1, pids, 32);
         if (decrypt_cwl_file(ts, "test/multi.p1.ts", &log, 300, 0, 0,
                               pids, np, 0, 1, &st) == RET_OK)
         {
            check("program 1 decrypts", st.decrypted_packets > 0, "nothing");
            check("program 1 syncs once", st.sync_count == 1, "wrong count");
            /* the pids of the other service must be untouched */
            check("the other service is left alone",
                  st.dropped_packets == 0 &&
                  st.passthrough_packets > 0, "something was dropped");
            snprintf(detail, sizeof(detail), "%lu decrypted",
                     st.decrypted_packets);
            printf ("        %s\n", detail);
         }
         else
         {
            check("program 1 decrypts", 0, "the run failed");
         }
         cwl_free(&log);
      }
      else
      {
         check("program 1 decrypts", 0, "the log would not load");
      }
   }

   printf ("  psi: %s\n", bad ? "FAIL" : "OK");
   return bad ? 1 : 0;
}
