

#include <iostream>

#include <string.h>
#include <signal.h>


void handler(int nSignum, siginfo_t* si, void* vcontext) {
  std::cout << "Segmentation fault" << std::endl;
  
  ucontext_t* context = (ucontext_t*)vcontext;
  context->uc_mcontext.gregs[REG_RIP]++;
}


int main() {
  std::cout << "Start" << std::endl;
  
  struct sigaction action;
  memset(&action, 0, sizeof(struct sigaction));
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = handler;
  sigaction(SIGSEGV, &action, NULL);
  
  int* x = 0;
  int y = *x;
  
  std::cout << "End" << std::endl;
  
  return 0;
}
