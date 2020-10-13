#include "semaphore.h"

#include <iostream>

#include "shared.h"

semaphore::semaphore(size_t val) : val_(val) {}

void semaphore::up() {
  enter_critical_section();

  ++val_;

  if (!wait_queue_.empty()) {
    ready_thread(wait_queue_.front());
    wait_queue_.pop_front();
  }

  leave_critical_section();
}

void semaphore::down() {
  enter_critical_section();

  while (val_ == 0) {
    block_thread(&wait_queue_);
  }

  --val_;

  leave_critical_section();
}

semaphore::semaphore(const semaphore& sem) {
  enter_critical_section();
  val_ = sem.val_;
  leave_critical_section();
}
semaphore::semaphore(semaphore&& sem) {
  enter_critical_section();
  val_ = sem.val_;
  leave_critical_section();
}
