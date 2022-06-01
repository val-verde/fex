#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile bool loop = true;
volatile bool last = false;
volatile int count = 0;
volatile int count2 = 0;

// OPTIONS
// TESTSIGPROCMASK

#define NUMCOUNT 10
#define SIGN SIGTSTP

void sig_handler(int signum) {
  printf("Inside handler function\n");

  if (last) {
    printf("Handling last raise\n");
    loop = false;
    return;
  }

  if (count2 != count) {
    printf("Signal reentering bug\n");
    exit(-1);
  }
  loop = false;
  if (count < NUMCOUNT) {
    printf("Nested Raising %d, %d of %d times\n", signum, 1 + count, NUMCOUNT);
    count2++;
    raise(signum);
    count++;
  }
}

int main() {
  if (signal(SIGN, sig_handler) != 0) {
    printf("Signal() failed\n");
    return -2;
  }

  // test if sigmask blocks during execution as expected
  last = false;
  loop = true;
  while (loop) {
    printf("Inside main loop, raising signal\n");
    raise(SIGN);
  }
  last = true;
  loop = true;
  // test if sigmask returned by sigprocmask is the one set by the signal return
#if defined(TESTSIGPROCMASK)
  sigset_t old;
  sigprocmask(0, 0, &old);
  sigprocmask(SIG_SETMASK, &old, 0);
#endif
  while (loop) {
    printf("Inside last loop, raising signal\n");
    raise(SIGN);
    if (loop) {
      printf("Error: Signal did not get raised\n");
      return -3;
    }
  }
  printf("All good, Exiting\n");
  return 0;
}
