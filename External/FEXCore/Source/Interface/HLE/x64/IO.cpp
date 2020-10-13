#include "Interface/HLE/Syscalls.h"
#include "Interface/HLE/x64/Syscalls.h"

#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::HLE::x64{
  void RegisterIO() {
    REGISTER_SYSCALL_IMPL_X64(io_getevents, [](FEXCore::Core::InternalThreadState *Thread, aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout) -> uint64_t {
      uint64_t Result = ::syscall(SYS_io_getevents, ctx_id, min_nr, nr, events, timeout);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL_X64(io_pgetevents, [](FEXCore::Core::InternalThreadState *Thread, aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout, const struct io_sigset  *usig) -> uint64_t {
      uint64_t Result = ::syscall(SYS_io_pgetevents, ctx_id, min_nr, nr, events, timeout);
      SYSCALL_ERRNO();
    });
  }
}
