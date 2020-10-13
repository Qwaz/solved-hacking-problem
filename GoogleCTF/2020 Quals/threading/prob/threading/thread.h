#ifndef EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_THREAD_H_
#define EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_THREAD_H_

#include <functional>
#include <memory>

// Cause the current thread to yield its native thread and be moved to the back
// of the ready queue.
void yield();

// Sets the maximum number of native threads to use. Until this number is
// reached, new threads will be backed by a native thread. Once this number
// is reached, native threads will start to be shared. May not be called after
// threads have been created.
void set_max_native_threads(int threads);

// Sleep for the specified number of microseconds in a thread safe way. Does
// not yield the underlying native thread.
void uthread_safe_sleep(uint64_t microseconds);

struct thread_control_block;

class uthread {
 public:
  uthread() = default;
  uthread(std::function<void()> callable);
  void join();

  uthread(const uthread& other) = default;
  uthread(uthread&& other) = default;
  uthread& operator=(const uthread& other) = default;

  std::shared_ptr<thread_control_block> tcb_;
};

#endif  // EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_THREAD_H_
