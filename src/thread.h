/* Minimal threading primitives.
 *
 * Windows uses the Win32 API, everything else uses POSIX threads, so the rest
 * of the code stays free of #ifdef noise. Only what the decrypt pipeline needs
 * is implemented. */

#ifndef TSDEC_THREAD_H
#define TSDEC_THREAD_H

#if defined(_WIN32)
# define WIN32_LEAN_AND_MEAN
# include <windows.h>

typedef HANDLE    tsdec_thread_t;
typedef CRITICAL_SECTION tsdec_mutex_t;
typedef CONDITION_VARIABLE tsdec_cond_t;

typedef struct
{
   void *(*fn)(void *);
   void  *arg;
} tsdec_thread_trampoline_t;

static DWORD WINAPI tsdec_thread_entry (LPVOID p)
{
   tsdec_thread_trampoline_t *s = (tsdec_thread_trampoline_t *) p;
   s->fn(s->arg);
   free(s);
   return 0;
}

#define mutex_init(m)      InitializeCriticalSection(m)
#define mutex_lock(m)      EnterCriticalSection(m)
#define mutex_unlock(m)    LeaveCriticalSection(m)
#define mutex_destroy(m)   DeleteCriticalSection(m)
#define cond_init(c)       InitializeConditionVariable(c)
#define cond_wait(c, m)    SleepConditionVariableCS(c, m, INFINITE)
#define cond_signal(c)     WakeConditionVariable(c)
#define cond_broadcast(c)  WakeAllConditionVariable(c)
#define cond_destroy(c)    ((void) (c))

static int tsdec_thread_start (tsdec_thread_t *t, void *(*fn)(void *), void *arg)
{
   /* CreateThread wants a DWORD(WINAPI *)(void *), which is a different
    * calling convention from void *(*)(void *). Route through a trampoline
    * instead of casting, which is undefined behaviour on x64. */
   tsdec_thread_trampoline_t *s = (tsdec_thread_trampoline_t *)
      malloc(sizeof(*s));
   if (!s)
      return -1;
   s->fn = fn;
   s->arg = arg;
   *t = CreateThread(NULL, 0, tsdec_thread_entry, s, 0, NULL);
   if (!*t)
   {
      free(s);
      return -1;
   }
   return 0;
}

static int tsdec_thread_join (tsdec_thread_t t)
{
   WaitForSingleObject(t, INFINITE);
   CloseHandle(t);
   return 0;
}

static int tsdec_cpu_count (void)
{
   SYSTEM_INFO si;
   GetSystemInfo(&si);
   return (int) si.dwNumberOfProcessors;
}

#else
# include <pthread.h>
# include <unistd.h>

typedef pthread_t tsdec_thread_t;
typedef pthread_mutex_t tsdec_mutex_t;
typedef pthread_cond_t  tsdec_cond_t;

#define mutex_init(m)      pthread_mutex_init(m, NULL)
#define mutex_lock(m)      pthread_mutex_lock(m)
#define mutex_unlock(m)    pthread_mutex_unlock(m)
#define mutex_destroy(m)   pthread_mutex_destroy(m)
#define cond_init(c)       pthread_cond_init(c, NULL)
#define cond_wait(c, m)    pthread_cond_wait(c, m)
#define cond_signal(c)     pthread_cond_signal(c)
#define cond_broadcast(c)  pthread_cond_broadcast(c)
#define cond_destroy(c)    pthread_cond_destroy(c)

static int tsdec_thread_start (tsdec_thread_t *t, void *(*fn)(void *), void *arg)
{
   return pthread_create(t, NULL, fn, arg);
}

static int tsdec_thread_join (tsdec_thread_t t)
{
   return pthread_join(t, NULL);
}

static int tsdec_cpu_count (void)
{
   long n = sysconf(_SC_NPROCESSORS_ONLN);
   return n > 0 ? (int) n : 1;
}

#endif

#endif
