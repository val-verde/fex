#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>

volatile bool loop = true;
volatile bool inhandler = false;

#define NUMCOUNT 10
#define SIGN SIGTSTP

void sig_handler(int signum, siginfo_t *info, void *context) {
  printf("Inside handler function\n");
  if (inhandler) {
    printf("Signal reentering bug\n");
    exit(-1);
  }
  inhandler = true;
  loop = false;
  raise(signum);

  auto uctx = (ucontext_t *)context;
  sigfillset(&uctx->uc_sigmask);
}

int main() {
  struct sigaction act = {0};

  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = &sig_handler;
  if (sigaction(SIGN, &act, NULL) != 0) {
    printf("sigaction() failed\n");
    return -2;
  }
  while (loop) {
    printf("Inside main loop, raising signal\n");
    raise(SIGN);
  }
  printf("Exiting\n");
  return 0;
}
