/* Cancellation test.
 *
 * Spawns a thread that asks the job to stop after a moment, runs a decrypt
 * that is deliberately much larger than that moment, and checks that the run
 * stops early, reports it, and leaves packet aligned output behind.
 *
 * This drives the same path the GUI uses: tsdec_request_cancel() from another
 * thread, no signal involved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "csa.h"
#include "thread.h"
#include "tsdec.h"

typedef struct
{
   unsigned long delay_ms;
} canceller_t;

static void *canceller_main (void *arg)
{
   canceller_t *c = (canceller_t *) arg;
   unsigned long i;

   for (i = 0; i < c->delay_ms / 10; i++)
      sleep_ms(10);
   tsdec_request_cancel();
   return NULL;
}

int main (int argc, char **argv)
{
   const char *ifile = argc > 1 ? argv[1] : "test/huge.enc.ts";
   const char *cwl  = argc > 2 ? argv[2] : "test/huge.cwl";
   const char *ofile = argc > 3 ? argv[3] : "test/cancel_out.ts";
   int nworkers = argc > 4 ? atoi(argv[4]) : 1;
   unsigned long delay = argc > 5 ? strtoul(argv[5], NULL, 10) : 600;
   cwl_t log;
   tsdec_job_t job;
   stats_t stats;
   tsdec_thread_t th;
   canceller_t c;
   FILE *f;
   long long size;
   int ret, bad = 0;

   if (cwl_load(cwl, &log, 1, 0) != RET_OK)
   {
      fprintf(stderr, "cannot load %s\n", cwl);
      return 1;
   }

   remove(ofile);

   tsdec_job_init(&job);
   job.ifile = ifile;
   job.ofile = ofile;
   job.cwl = &log;
   job.nworkers = nworkers;
   job.verbose = 1;

   c.delay_ms = delay;
   tsdec_thread_start(&th, canceller_main, &c);

   ret = tsdec_run(&job, &stats);
   tsdec_thread_join(th);
   cwl_free(&log);

   if (ret != RET_CANCELED)
   {
      printf("  FAIL: expected RET_CANCELED (%d), got %d\n", RET_CANCELED, ret);
      bad++;
   }
   else
   {
      printf("  stopped at %lu of the packets read, canceled flag set\n",
             stats.total_packets);
   }

   if (!stats.canceled)
   {
      printf("  FAIL: stats.canceled was not set\n");
      bad++;
   }

   f = fopen(ofile, "rb");
   if (!f)
   {
      printf("  FAIL: no output file\n");
      bad++;
   }
   else
   {
      fseek(f, 0, SEEK_END);
      size = ftell(f);
      fclose(f);

      if (size == 0)
      {
         printf("  FAIL: output is empty\n");
         bad++;
      }
      else if (size % PCKTSIZE)
      {
         printf("  FAIL: output is %lld bytes, not packet aligned\n", size);
         bad++;
      }
      else
      {
         printf("  output is %lld packets, packet aligned\n", size / PCKTSIZE);
      }
   }

   printf("  %s\n", bad ? "FAIL" : "OK");
   return bad ? 1 : 0;
}
