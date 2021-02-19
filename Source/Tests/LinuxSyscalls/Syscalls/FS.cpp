#include "Tests/LinuxSyscalls/Syscalls.h"
#include "Tests/LinuxSyscalls/x64/Syscalls.h"
#include "Tests/LinuxSyscalls/x32/Syscalls.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/fanotify.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/xattr.h>

#define GET_PATH(pathname) (pathname ? FEX::HLE::_SyscallHandler->FM.GetEmulatedPath(pathname).c_str() : nullptr)


namespace FEX::HLE {
  void RegisterFS() {
    REGISTER_SYSCALL_IMPL(getcwd, [](FEXCore::Core::CpuStateFrame *Frame, char *buf, size_t size) -> uint64_t {
      uint64_t Result = syscall(SYS_getcwd, buf, size);
      if (Result != -1) {
        auto rootpath = FEX::HLE::_SyscallHandler->FM.GetEmulatedPath("/");
        for (int i = rootpath.size() - 1, j = 0; buf[i]; i++, j++) {
          buf[j] = buf[i];
          buf[j+1] = 0;
        }
      }
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(chdir, [](FEXCore::Core::CpuStateFrame *Frame, const char *path) -> uint64_t {
      uint64_t Result = ::chdir(GET_PATH(path));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(fchdir, [](FEXCore::Core::CpuStateFrame *Frame, int fd) -> uint64_t {
      uint64_t Result = ::fchdir(fd);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(rename, [](FEXCore::Core::CpuStateFrame *Frame, const char *oldpath, const char *newpath) -> uint64_t {
      uint64_t Result = ::rename(GET_PATH(oldpath), GET_PATH(newpath));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(mkdir, [](FEXCore::Core::CpuStateFrame *Frame, const char *pathname, mode_t mode) -> uint64_t {
      uint64_t Result = ::mkdir(GET_PATH(pathname), mode);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(rmdir, [](FEXCore::Core::CpuStateFrame *Frame, const char *pathname) -> uint64_t {
      uint64_t Result = ::rmdir(GET_PATH(pathname));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(link, [](FEXCore::Core::CpuStateFrame *Frame, const char *oldpath, const char *newpath) -> uint64_t {
      uint64_t Result = ::link(GET_PATH(oldpath), GET_PATH(newpath));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(unlink, [](FEXCore::Core::CpuStateFrame *Frame, const char *pathname) -> uint64_t {
      uint64_t Result = ::unlink(GET_PATH(pathname));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(symlink, [](FEXCore::Core::CpuStateFrame *Frame, const char *target, const char *linkpath) -> uint64_t {
      uint64_t Result = ::symlink(GET_PATH(target), GET_PATH(linkpath));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(readlink, [](FEXCore::Core::CpuStateFrame *Frame, const char *pathname, char *buf, size_t bufsiz) -> uint64_t {
      uint64_t Result = FEX::HLE::_SyscallHandler->FM.Readlink(pathname, buf, bufsiz);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(chmod, [](FEXCore::Core::CpuStateFrame *Frame, const char *pathname, mode_t mode) -> uint64_t {
      uint64_t Result = ::chmod(GET_PATH(pathname), mode);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(umask, [](FEXCore::Core::CpuStateFrame *Frame, mode_t mask) -> uint64_t {
      uint64_t Result = ::umask(mask);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(mknod, [](FEXCore::Core::CpuStateFrame *Frame, const char *pathname, mode_t mode, dev_t dev) -> uint64_t {
      uint64_t Result = FEX::HLE::_SyscallHandler->FM.Mknod(pathname, mode, dev);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(ustat, [](FEXCore::Core::CpuStateFrame *Frame, dev_t dev, struct ustat *ubuf) -> uint64_t {
      // Since version 2.28 of GLIBC it has stopped providing a wrapper for this syscall
#ifdef SYS_ustat
      uint64_t Result = syscall(SYS_ustat, dev, ubuf);
      SYSCALL_ERRNO();
#else
      return -ENOSYS;
#endif
    });

    /*
      arg1 is one of: void, unsigned int fs_index, const char *fsname
      arg2 is one of: void, char *buf
    */
    REGISTER_SYSCALL_IMPL(sysfs, [](FEXCore::Core::CpuStateFrame *Frame, int option,  uint64_t arg1,  uint64_t arg2) -> uint64_t {
#ifdef SYS_sysfs
      uint64_t Result = syscall(SYS_sysfs, option, arg1, arg2);
      SYSCALL_ERRNO();
#else
      return -ENOSYS;
#endif
    });

    REGISTER_SYSCALL_IMPL(statfs, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, struct statfs *buf) -> uint64_t {
      uint64_t Result = FEX::HLE::_SyscallHandler->FM.Statfs(path, buf);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(fstatfs, [](FEXCore::Core::CpuStateFrame *Frame, int fd, struct statfs *buf) -> uint64_t {
      uint64_t Result = ::fstatfs(fd, buf);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(truncate, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, off_t length) -> uint64_t {
      uint64_t Result = ::truncate(GET_PATH(path), length);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(creat, [](FEXCore::Core::CpuStateFrame *Frame, const char *pathname, mode_t mode) -> uint64_t {
      uint64_t Result = ::creat(GET_PATH(pathname), mode);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(chroot, [](FEXCore::Core::CpuStateFrame *Frame, const char *path) -> uint64_t {
      uint64_t Result = ::chroot(GET_PATH(path));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(sync, [](FEXCore::Core::CpuStateFrame *Frame) -> uint64_t {
      sync();
      return 0; // always successful
    });

    REGISTER_SYSCALL_IMPL(acct, [](FEXCore::Core::CpuStateFrame *Frame, const char *filename) -> uint64_t {
      uint64_t Result = ::acct(GET_PATH(filename));
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(mount, [](FEXCore::Core::CpuStateFrame *Frame, const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data) -> uint64_t {
      uint64_t Result = ::mount(GET_PATH(source), GET_PATH(target), filesystemtype, mountflags, data);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(umount2, [](FEXCore::Core::CpuStateFrame *Frame, const char *target, int flags) -> uint64_t {
      uint64_t Result = ::umount2(GET_PATH(target), flags);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(swapon, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, int swapflags) -> uint64_t {
      uint64_t Result = ::swapon(GET_PATH(path), swapflags);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(swapoff, [](FEXCore::Core::CpuStateFrame *Frame, const char *path) -> uint64_t {
      uint64_t Result = ::swapoff(GET_PATH(path));
      SYSCALL_ERRNO();
    });


    /*
    REGISTER_SYSCALL_IMPL(syncfs, [](FEXCore::Core::CpuStateFrame *Frame, int fd) -> uint64_t {
      SYSCALL_STUB(syncfs);
    });*/
    REGISTER_SYSCALL_FORWARD_ERRNO(syncfs);

    REGISTER_SYSCALL_IMPL(setxattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, const char *name, const void *value, size_t size, int flags) -> uint64_t {
      uint64_t Result = ::setxattr(GET_PATH(path), name, value, size, flags);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(lsetxattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, const char *name, const void *value, size_t size, int flags) -> uint64_t {
      uint64_t Result = ::lsetxattr(GET_PATH(path), name, value, size, flags);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(fsetxattr, [](FEXCore::Core::CpuStateFrame *Frame, int fd, const char *name, const void *value, size_t size, int flags) -> uint64_t {
      uint64_t Result = ::fsetxattr(fd, name, value, size, flags);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(getxattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, const char *name, void *value, size_t size) -> uint64_t {
      uint64_t Result = ::getxattr(GET_PATH(path), name, value, size);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(lgetxattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, const char *name, void *value, size_t size) -> uint64_t {
      uint64_t Result = ::lgetxattr(GET_PATH(path), name, value, size);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(fgetxattr, [](FEXCore::Core::CpuStateFrame *Frame, int fd, const char *name, void *value, size_t size) -> uint64_t {
      uint64_t Result = ::fgetxattr(fd, name, value, size);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(listxattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, char *list, size_t size) -> uint64_t {
      uint64_t Result = ::listxattr(GET_PATH(path), list, size);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(llistxattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, char *list, size_t size) -> uint64_t {
      uint64_t Result = ::llistxattr(GET_PATH(path), list, size);
      SYSCALL_ERRNO();
    });

    /*
    REGISTER_SYSCALL_IMPL(flistxattr, [](FEXCore::Core::CpuStateFrame *Frame, int fd, char *list, size_t size) -> uint64_t {
      SYSCALL_STUB(flistxattr);
    });*/
    REGISTER_SYSCALL_FORWARD_ERRNO(flistxattr);

    REGISTER_SYSCALL_IMPL(removexattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, const char *name) -> uint64_t {
      uint64_t Result = ::removexattr(GET_PATH(path), name);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(lremovexattr, [](FEXCore::Core::CpuStateFrame *Frame, const char *path, const char *name) -> uint64_t {
      uint64_t Result = ::lremovexattr(GET_PATH(path), name);
      SYSCALL_ERRNO();
    });

    /*
    REGISTER_SYSCALL_IMPL(fremovexattr, [](FEXCore::Core::CpuStateFrame *Frame, int fd, const char *name) -> uint64_t {
      SYSCALL_STUB(fremovexattr);
    });*/
    REGISTER_SYSCALL_FORWARD_ERRNO(fremovexattr);

    REGISTER_SYSCALL_IMPL(fanotify_init, [](FEXCore::Core::CpuStateFrame *Frame, unsigned int flags, unsigned int event_f_flags) -> uint64_t {
      uint64_t Result = ::fanotify_init(flags, event_f_flags);
      SYSCALL_ERRNO();
    });

    REGISTER_SYSCALL_IMPL(fanotify_mark, [](FEXCore::Core::CpuStateFrame *Frame, int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname) -> uint64_t {
      uint64_t Result = ::fanotify_mark(fanotify_fd, flags, mask, dirfd, GET_PATH(pathname));
      SYSCALL_ERRNO();
    });
  }
}
