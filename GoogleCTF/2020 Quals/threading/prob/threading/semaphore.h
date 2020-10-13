#ifndef EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SEMAPHORE_H_
#define EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SEMAPHORE_H_

#include "shared.h"

struct semaphore {
  semaphore(size_t val);
  void up();
  void down();
  semaphore(const semaphore& sem);
  semaphore(semaphore&& sem);
  
 private:
  size_t val_;
  std::deque<ucontext_t*> wait_queue_;
};

#endif  // EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SEMAPHORE_H_
