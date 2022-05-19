
#include "Interface/Core/ArchHelpers/MContext.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/X86HelperGen.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/UContext.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Event.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <signal.h>

namespace FEXCore::CPU {

void Dispatcher::SleepThread(FEXCore::Context::Context *ctx, FEXCore::Core::CpuStateFrame *Frame) {
  auto Thread = Frame->Thread;

  --ctx->IdleWaitRefCount;
  ctx->IdleWaitCV.notify_all();

  Thread->RunningEvents.ThreadSleeping = true;

  // Go to sleep
  Thread->StartRunning.Wait();

  Thread->RunningEvents.Running = true;
  ++ctx->IdleWaitRefCount;
  Thread->RunningEvents.ThreadSleeping = false;

  ctx->IdleWaitCV.notify_all();
}

ArchHelpers::Context::ContextBackup *Dispatcher::StoreThreadState(int Signal, void *ucontext, uint64_t *GuestRSP) {
  // We can end up getting a signal at any point in our host state
  // Jump to a handler that saves all state so we can safely return
  uintptr_t NewGuestSP = *GuestRSP;

  size_t StackOffset = sizeof(ArchHelpers::Context::ContextBackup);

  NewGuestSP -= StackOffset;
  NewGuestSP = AlignDown(NewGuestSP, alignof(ArchHelpers::Context::ContextBackup));

  auto Context = reinterpret_cast<ArchHelpers::Context::ContextBackup*>(NewGuestSP);
  ArchHelpers::Context::BackupContext(ucontext, Context);

  // Retain the action pointer so we can see it when we return
  Context->Signal = Signal;

  Context->Flags = 0;
  Context->FPStateLocation = 0;
  Context->UContextLocation = 0;
  Context->SigInfoLocation = 0;

  // Store fault to top status and then reset it
  Context->FaultToTopAndGeneratedException = SynchronousFaultData.FaultToTopAndGeneratedException;
  SynchronousFaultData.FaultToTopAndGeneratedException = false;

  *GuestRSP = NewGuestSP;
  return Context;
}

void doRestoreThreadState(FEXCore::Core::CpuStateFrame *Frame, void *ucontext, ArchHelpers::Context::ContextBackup* Context, uint64_t AbsoluteLoopTopAddressFillSRA) {

  ArchHelpers::Context::RestoreContext(ucontext, Context);

  if (Context->UContextLocation) {
    if (Context->Flags &ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INJIT) {
      // XXX: Unsupported since it needs state reconstruction
      // If we are in the JIT then SRA might need to be restored to values from the context
      // We can't currently support this since it might result in tearing without real state reconstruction
    }

    if (!(Context->Flags & ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_32BIT)) {
      auto *guest_uctx = reinterpret_cast<FEXCore::x86_64::ucontext_t*>(Context->UContextLocation);
      [[maybe_unused]] auto *guest_siginfo = reinterpret_cast<siginfo_t*>(Context->SigInfoLocation);

      // If the guest modified the RIP then we need to take special precautions here
      if (Context->OriginalRIP != guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_RIP] ||
          Context->FaultToTopAndGeneratedException) {
        // Hack! Go back to the top of the dispatcher top
        //FEX_TODO("thunk error handling here")
        // This is only safe inside the JIT rather than anything outside of it
        ArchHelpers::Context::SetPc(ucontext, AbsoluteLoopTopAddressFillSRA);
        // Set our state register to point to our guest thread data
        ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));
        ArchHelpers::Context::SetSp(ucontext, Frame->ReturningStackLocation);
      }

      // Restore from mcontext
      Frame->State.rip = guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_RIP];
      // XXX: Full context setting
      uint32_t eflags = guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_EFL];
      for (size_t i = 0; i < 32; ++i) {
        Frame->State.flags[i] = (eflags & (1U << i)) ? 1 : 0;
      }

      Frame->State.flags[1] = 1;
      Frame->State.flags[9] = 1;

#define COPY_REG(x) \
          Frame->State.gregs[X86State::REG_##x] = guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_##x];
          COPY_REG(R8);
          COPY_REG(R9);
          COPY_REG(R10);
          COPY_REG(R11);
          COPY_REG(R12);
          COPY_REG(R13);
          COPY_REG(R14);
          COPY_REG(R15);
          COPY_REG(RDI);
          COPY_REG(RSI);
          COPY_REG(RBP);
          COPY_REG(RBX);
          COPY_REG(RDX);
          COPY_REG(RAX);
          COPY_REG(RCX);
          COPY_REG(RSP);
#undef COPY_REG
      FEXCore::x86_64::_libc_fpstate *fpstate = reinterpret_cast<FEXCore::x86_64::_libc_fpstate*>(guest_uctx->uc_mcontext.fpregs);
      // Copy float registers
      memcpy(Frame->State.mm, fpstate->_st, sizeof(Frame->State.mm));
      memcpy(Frame->State.xmm, fpstate->_xmm, sizeof(Frame->State.xmm));

      // FCW store default
      Frame->State.FCW = fpstate->fcw;
      Frame->State.FTW = fpstate->ftw;

      // Deconstruct FSW
      Frame->State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (fpstate->fsw >> 8) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (fpstate->fsw >> 9) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (fpstate->fsw >> 10) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (fpstate->fsw >> 14) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (fpstate->fsw >> 11) & 0b111;

      // Tell signal delegator about this
      memcpy(&(((ucontext_t*)ucontext)->uc_sigmask), &guest_uctx->uc_sigmask, sizeof(guest_uctx->uc_sigmask));
      Frame->Thread->CTX->SignalDelegation->GuestSigNotifyMask(&(((ucontext_t*)ucontext)->uc_sigmask));
    }
    else {
      auto *guest_uctx = reinterpret_cast<FEXCore::x86::ucontext_t*>(Context->UContextLocation);
      [[maybe_unused]] auto *guest_siginfo = reinterpret_cast<FEXCore::x86::siginfo_t*>(Context->SigInfoLocation);
      // If the guest modified the RIP then we need to take special precautions here
      if (Context->OriginalRIP != guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_EIP] ||
          Context->FaultToTopAndGeneratedException) {
        // Hack! Go back to the top of the dispatcher top
        // This is only safe inside the JIT rather than anything outside of it
        ArchHelpers::Context::SetPc(ucontext, AbsoluteLoopTopAddressFillSRA);
        // Set our state register to point to our guest thread data
        ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));
        //FEX_TODO("Thunk longjump")
        ArchHelpers::Context::SetSp(ucontext, Frame->ReturningStackLocation);

      }
      // XXX: Full context setting
      // First 32-bytes of flags is EFLAGS broken out
      uint32_t eflags = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_EFL];
      for (size_t i = 0; i < 32; ++i) {
        Frame->State.flags[i] = (eflags & (1U << i)) ? 1 : 0;
      }

      Frame->State.flags[1] = 1;
      Frame->State.flags[9] = 1;

      Frame->State.rip = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_EIP];
      Frame->State.cs = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_CS];
      Frame->State.ds = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_DS];
      Frame->State.es = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_ES];
      Frame->State.fs = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_FS];
      Frame->State.gs = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_GS];
      Frame->State.ss = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_SS];
#define COPY_REG(x) \
    Frame->State.gregs[X86State::REG_##x] = guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_##x];
      COPY_REG(RDI);
      COPY_REG(RSI);
      COPY_REG(RBP);
      COPY_REG(RBX);
      COPY_REG(RDX);
      COPY_REG(RAX);
      COPY_REG(RCX);
      COPY_REG(RSP);
#undef COPY_REG
      FEXCore::x86::_libc_fpstate *fpstate = reinterpret_cast<FEXCore::x86::_libc_fpstate*>(guest_uctx->uc_mcontext.fpregs);

      // Copy float registers
      for (size_t i = 0; i < 8; ++i) {
        // 32-bit st register size is only 10 bytes. Not padded to 16byte like x86-64
        memcpy(&Frame->State.mm[i], &fpstate->_st[i], 10);
      }

      // Extended XMM state
      memcpy(fpstate->_xmm, Frame->State.xmm, sizeof(Frame->State.xmm));

      // FCW store default
      Frame->State.FCW = fpstate->fcw;
      Frame->State.FTW = fpstate->ftw;

      // Deconstruct FSW
      Frame->State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (fpstate->fsw >> 8) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (fpstate->fsw >> 9) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (fpstate->fsw >> 10) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (fpstate->fsw >> 14) & 1;
      Frame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (fpstate->fsw >> 11) & 0b111;

      // Tell signal delegator about this
      memcpy(&(((ucontext_t*)ucontext)->uc_sigmask), &guest_uctx->uc_sigmask, sizeof(guest_uctx->uc_sigmask));
      Frame->Thread->CTX->SignalDelegation->GuestSigNotifyMask(&(((ucontext_t*)ucontext)->uc_sigmask));
    }
  }
}

static uint32_t ConvertSignalToTrapNo(int Signal, siginfo_t *HostSigInfo) {
  switch (Signal) {
    case SIGSEGV:
      if (HostSigInfo->si_code == SEGV_MAPERR ||
          HostSigInfo->si_code == SEGV_ACCERR) {
        // Protection fault
        return X86State::X86_TRAPNO_PF;
      }
      break;
  }

  // Unknown mapping, fall back to old behaviour and just pass signal
  return Signal;
}

static uint32_t ConvertSignalToError(int Signal, siginfo_t *HostSigInfo) {
  switch (Signal) {
    case SIGSEGV:
      if (HostSigInfo->si_code == SEGV_MAPERR ||
          HostSigInfo->si_code == SEGV_ACCERR) {
        // Protection fault
        // Always a user fault for us
        // XXX: PF_PROT and PF_WRITE
        return X86State::X86_PF_USER;
      }
      break;
  }

  // Not a page fault issue
  return 0;
}

bool Dispatcher::HandleGuestSignal(int Signal, void *info, void *ucontext, GuestSigAction *GuestAction, stack_t *GuestStack) {
  auto Frame = ThreadState->CurrentFrame;

  // Ref count our faults
  // We use this to track if it is safe to clear cache
  ++SignalHandlerRefCounter;

  // Pulling from context here
  bool Is64BitMode = CTX->Config.Is64BitMode;

  bool InJIT = false;
  uint64_t OldPC = ArchHelpers::Context::GetPc(ucontext);
  
  // Spill the SRA regardless of signal handler type
  // We are going to be returning to the top of the dispatcher which will fill again
  // Otherwise we might load garbage
  if (SRAEnabled) {
    if (IsAddressInJITCode(OldPC, false)) {
      uint32_t IgnoreMask{};
#ifdef _M_ARM_64
      if (Frame->InSyscallInfo != 0) {
        // We are in a syscall, this means we are in a weird register state
        // We need to spill SRA but only some of it, since some values have already been spilled
        // Lower 16 bits tells us which registers are already spilled to the context
        // So we ignore spilling those ones
        uint16_t NumRegisters = std::popcount(Frame->InSyscallInfo & 0xFFFF);
        if (NumRegisters >= 4) {
          // Unhandled case
          IgnoreMask = 0;
        }
        else {
          IgnoreMask = Frame->InSyscallInfo & 0xFFFF;
        }
      }
      else {
        // We must spill everything
        IgnoreMask = 0;
      }
#endif

      // We are in jit, SRA must be spilled
      SpillSRA(ucontext, IgnoreMask);
      InJIT = true;
    } else {
      if (!IsAddressInJITCode(OldPC, true)) {
        // This is likely to cause issues but in some cases it isn't fatal
        // This can also happen if we have put a signal on hold, then we just reenabled the signal
        // So we are in the syscall handler
        // Only throw a log message in this case
        if constexpr (false) {
          // XXX: Messages in the signal handler can cause us to crash
          LogMan::Msg::EFmt("Signals in dispatcher have unsynchronized context");
        }
      }
    }
  }

  // RSP is (mostly) guaranteed to be reconstructed here. Pending some SRA fixes to make it always.
  uint64_t OldGuestSP = Frame->State.gregs[X86State::REG_RSP];
  uint64_t NewGuestSP = OldGuestSP;

  // altstack is only used if the signal handler was setup with SA_ONSTACK
  if (GuestAction->sa_flags & SA_ONSTACK) {
    // Additionally the altstack is only used if the enabled (SS_DISABLE flag is not set)
    if (!(GuestStack->ss_flags & SS_DISABLE)) {
      // If our guest is already inside of the alternative stack
      // Then that means we are hitting recursive signals and we need to walk back the stack correctly
      uint64_t AltStackBase = reinterpret_cast<uint64_t>(GuestStack->ss_sp);
      uint64_t AltStackEnd = AltStackBase + GuestStack->ss_size;
      if (OldGuestSP >= AltStackBase &&
          OldGuestSP <= AltStackEnd) {
        // We are already in the alt stack, the rest of the code will handle adjusting this
      }
      else {
        NewGuestSP = AltStackEnd;
      }
    }
  }

  if (Is64BitMode) {
    // Back up past the redzone, which is 128bytes
    // 32-bit doesn't have a redzone
    NewGuestSP -= 128;
  }

  NewGuestSP = AlignDown(NewGuestSP, 16);

  // Backup Host stack in guest stack
  auto HostStackSize  = Frame->ReturningStackLocation - ArchHelpers::Context::GetSp(ucontext) + 16;
  HostStackSize += ArchHelpers::Context::ContextBackup::RedZoneSize;
  HostStackSize = AlignUp(HostStackSize, 16);

  NewGuestSP -= HostStackSize;

  auto HostStackStart = NewGuestSP;
  memcpy((void*)HostStackStart, (void*)(Frame->ReturningStackLocation - HostStackSize), HostStackSize);

  // Backup host context in guest stack
  auto ContextBackup = StoreThreadState(Signal, ucontext, &NewGuestSP);

  ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INJIT;

  ContextBackup->HostStackStart = HostStackStart;
  ContextBackup->HostStackSize = HostStackSize;

  // Reset jit execution
  ArchHelpers::Context::SetPc(ucontext, AbsoluteLoopTopAddressFillSRA);
  ArchHelpers::Context::SetSp(ucontext, Frame->ReturningStackLocation);

  // Set our state register to point to our guest thread data
  ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));

  // siginfo_t
  siginfo_t *HostSigInfo = reinterpret_cast<siginfo_t*>(info);

  // Backup where we think the RIP currently is
  ContextBackup->OriginalRIP = Frame->State.rip;

  // Setup ucontext a bit
  if (Is64BitMode) {
    NewGuestSP -= sizeof(FEXCore::x86_64::_libc_fpstate);
    NewGuestSP = AlignDown(NewGuestSP, alignof(FEXCore::x86_64::_libc_fpstate));
    uint64_t FPStateLocation = NewGuestSP;

    NewGuestSP -= sizeof(FEXCore::x86_64::ucontext_t);
    NewGuestSP = AlignDown(NewGuestSP, alignof(FEXCore::x86_64::ucontext_t));
    uint64_t UContextLocation = NewGuestSP;

    NewGuestSP -= sizeof(siginfo_t);
    NewGuestSP = AlignDown(NewGuestSP, alignof(siginfo_t));
    uint64_t SigInfoLocation = NewGuestSP;

    ContextBackup->FPStateLocation = FPStateLocation;
    ContextBackup->UContextLocation = UContextLocation;
    ContextBackup->SigInfoLocation = SigInfoLocation;

    FEXCore::x86_64::ucontext_t *guest_uctx = reinterpret_cast<FEXCore::x86_64::ucontext_t*>(UContextLocation);
    siginfo_t *guest_siginfo = reinterpret_cast<siginfo_t*>(SigInfoLocation);

    // We have extended float information
    guest_uctx->uc_flags = FEXCore::x86_64::UC_FP_XSTATE;

    // Pointer to where the fpreg memory is
    guest_uctx->uc_mcontext.fpregs = reinterpret_cast<FEXCore::x86_64::_libc_fpstate*>(FPStateLocation);
    FEXCore::x86_64::_libc_fpstate *fpstate = reinterpret_cast<FEXCore::x86_64::_libc_fpstate*>(FPStateLocation);

    guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_RIP] = Frame->State.rip;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_EFL] = 0;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_CSGSFS] = 0;

    // aarch64 and x86_64 siginfo_t matches. We can just copy this over
    // SI_USER could also potentially have random data in it, needs to be bit perfect
    // For guest faults we don't have a real way to reconstruct state to a real guest RIP
    *guest_siginfo = *HostSigInfo;

    if (ContextBackup->FaultToTopAndGeneratedException) {
      guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_TRAPNO] = SynchronousFaultData.TrapNo;
      guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_ERR] = SynchronousFaultData.err_code;

      // Overwrite si_code
      guest_siginfo->si_code = SynchronousFaultData.si_code;
    }
    else {
      guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_TRAPNO] = ConvertSignalToTrapNo(Signal, HostSigInfo);
      guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_ERR] = ConvertSignalToError(Signal, HostSigInfo);
    }
    guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_OLDMASK] = 0;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_CR2] = 0;

#define COPY_REG(x) \
    guest_uctx->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_##x] = Frame->State.gregs[X86State::REG_##x];
    COPY_REG(R8);
    COPY_REG(R9);
    COPY_REG(R10);
    COPY_REG(R11);
    COPY_REG(R12);
    COPY_REG(R13);
    COPY_REG(R14);
    COPY_REG(R15);
    COPY_REG(RDI);
    COPY_REG(RSI);
    COPY_REG(RBP);
    COPY_REG(RBX);
    COPY_REG(RDX);
    COPY_REG(RAX);
    COPY_REG(RCX);
    COPY_REG(RSP);
#undef COPY_REG

    // Copy float registers
    memcpy(fpstate->_st, Frame->State.mm, sizeof(Frame->State.mm));
    memcpy(fpstate->_xmm, Frame->State.xmm, sizeof(Frame->State.xmm));

    // FCW store default
    fpstate->fcw = Frame->State.FCW;
    fpstate->ftw = Frame->State.FTW;

    // Reconstruct FSW
    fpstate->fsw =
      (Frame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14);

    // Copy over signal stack information
    guest_uctx->uc_stack.ss_flags = GuestStack->ss_flags;
    guest_uctx->uc_stack.ss_sp = GuestStack->ss_sp;
    guest_uctx->uc_stack.ss_size = GuestStack->ss_size;
  }
  else {
    ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_32BIT;

    NewGuestSP -= sizeof(FEXCore::x86::_libc_fpstate);
    NewGuestSP = AlignDown(NewGuestSP, alignof(FEXCore::x86::_libc_fpstate));
    uint64_t FPStateLocation = NewGuestSP;

    NewGuestSP -= sizeof(FEXCore::x86::ucontext_t);
    NewGuestSP = AlignDown(NewGuestSP, alignof(FEXCore::x86::ucontext_t));
    uint64_t UContextLocation = NewGuestSP;

    NewGuestSP -= sizeof(FEXCore::x86::siginfo_t);
    NewGuestSP = AlignDown(NewGuestSP, alignof(FEXCore::x86::siginfo_t));
    uint64_t SigInfoLocation = NewGuestSP;

    ContextBackup->FPStateLocation = FPStateLocation;
    ContextBackup->UContextLocation = UContextLocation;
    ContextBackup->SigInfoLocation = SigInfoLocation;

    FEXCore::x86::ucontext_t *guest_uctx = reinterpret_cast<FEXCore::x86::ucontext_t*>(UContextLocation);
    FEXCore::x86::siginfo_t *guest_siginfo = reinterpret_cast<FEXCore::x86::siginfo_t*>(SigInfoLocation);

    // We have extended float information
    guest_uctx->uc_flags = FEXCore::x86::UC_FP_XSTATE;

    // Pointer to where the fpreg memory is
    guest_uctx->uc_mcontext.fpregs = static_cast<uint32_t>(FPStateLocation);
    FEXCore::x86::_libc_fpstate *fpstate = reinterpret_cast<FEXCore::x86::_libc_fpstate*>(FPStateLocation);

    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_GS] = Frame->State.gs;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_FS] = Frame->State.fs;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_ES] = Frame->State.es;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_DS] = Frame->State.ds;
    if (ContextBackup->FaultToTopAndGeneratedException) {
      guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_TRAPNO] = SynchronousFaultData.TrapNo;
      guest_siginfo->si_code = SynchronousFaultData.si_code;
      guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_ERR] = SynchronousFaultData.err_code;
    }
    else {
      guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_TRAPNO] = ConvertSignalToTrapNo(Signal, HostSigInfo);
      guest_siginfo->si_code = HostSigInfo->si_code;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_ERR] = ConvertSignalToError(Signal, HostSigInfo);
    }
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_EIP] = Frame->State.rip;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_CS] = Frame->State.cs;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_EFL] = 0;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_UESP] = 0;
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_SS] = Frame->State.ss;

#define COPY_REG(x) \
    guest_uctx->uc_mcontext.gregs[FEXCore::x86::FEX_REG_##x] = Frame->State.gregs[X86State::REG_##x];
    COPY_REG(RDI);
    COPY_REG(RSI);
    COPY_REG(RBP);
    COPY_REG(RBX);
    COPY_REG(RDX);
    COPY_REG(RAX);
    COPY_REG(RCX);
    COPY_REG(RSP);
#undef COPY_REG

    // Copy float registers
    for (size_t i = 0; i < 8; ++i) {
      // 32-bit st register size is only 10 bytes. Not padded to 16byte like x86-64
      memcpy(&fpstate->_st[i], &Frame->State.mm[i], 10);
    }

    // Extended XMM state
    fpstate->status = FEXCore::x86::fpstate_magic::MAGIC_XFPSTATE;
    memcpy(fpstate->_xmm, Frame->State.xmm, sizeof(Frame->State.xmm));

    // FCW store default
    fpstate->fcw = Frame->State.FCW;
    fpstate->ftw = Frame->State.FTW;
    // Reconstruct FSW
    fpstate->fsw =
      (Frame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
      (Frame->State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14);

    // Copy over signal stack information
    guest_uctx->uc_stack.ss_flags = GuestStack->ss_flags;
    guest_uctx->uc_stack.ss_sp = static_cast<uint32_t>(reinterpret_cast<uint64_t>(GuestStack->ss_sp));
    guest_uctx->uc_stack.ss_size = GuestStack->ss_size;

    // These three elements are in every siginfo
    guest_siginfo->si_signo = HostSigInfo->si_signo;
    guest_siginfo->si_errno = HostSigInfo->si_errno;

    switch (Signal) {
      case SIGSEGV:
      case SIGBUS:
        // Macro expansion to get the si_addr
        // This is the address trying to be accessed, not the RIP
        guest_siginfo->_sifields._sigfault.addr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(HostSigInfo->si_addr));
        break;
      case SIGFPE:
      case SIGILL:
        // Macro expansion to get the si_addr
        // Can't really give a real result here. Pull from the context for now
        guest_siginfo->_sifields._sigfault.addr = Frame->State.rip;
        break;
      case SIGCHLD:
        guest_siginfo->_sifields._sigchld.pid = HostSigInfo->si_pid;
        guest_siginfo->_sifields._sigchld.uid = HostSigInfo->si_uid;
        guest_siginfo->_sifields._sigchld.status = HostSigInfo->si_status;
        guest_siginfo->_sifields._sigchld.utime = HostSigInfo->si_utime;
        guest_siginfo->_sifields._sigchld.stime = HostSigInfo->si_stime;
        break;
      case SIGALRM:
      case SIGVTALRM:
        guest_siginfo->_sifields._timer.tid = HostSigInfo->si_timerid;
        guest_siginfo->_sifields._timer.overrun = HostSigInfo->si_overrun;
        guest_siginfo->_sifields._timer.sigval.sival_int = HostSigInfo->si_int;
        break;
      default:
        LogMan::Msg::EFmt("Unhandled siginfo_t for signal: {}\n", Signal);
        break;
    }
  }

  GuestSAMask NewMask { 0 };
  if (GuestAction->sa_flags & SA_SIGINFO) {
    Frame->State.rip = reinterpret_cast<uint64_t>(GuestAction->sigaction_handler.sigaction);
    NewMask = GuestAction->sa_mask;
  }
  else {
    Frame->State.rip = reinterpret_cast<uint64_t>(GuestAction->sigaction_handler.handler);
  }

  // SIG0 does not exist, or is part of this bitfield
  NewMask.Val |= 1 << (Signal - 1);

  // Tell signal delegator about this
  memcpy(&(((ucontext_t*)ucontext)->uc_sigmask), &NewMask, sizeof(NewMask));
  Frame->Thread->CTX->SignalDelegation->GuestSigNotifyMask(&(((ucontext_t*)ucontext)->uc_sigmask));
  

  while ((NewGuestSP & 15) != 8) {
    NewGuestSP--;
  }

  // the return depends on this
  NewGuestSP -= 8;
  *(uint64_t*)NewGuestSP = (uint64_t)ContextBackup;
  
  if (Is64BitMode) {
    Frame->State.gregs[X86State::REG_RDI] = ContextBackup->Signal;
    Frame->State.gregs[X86State::REG_RSI] = ContextBackup->SigInfoLocation;
    Frame->State.gregs[X86State::REG_RDX] = ContextBackup->UContextLocation;

    // Set up the new SP for stack handling
    NewGuestSP -= 8;
    *(uint64_t*)NewGuestSP = (uint64_t)GuestAction->restorer;
    Frame->State.gregs[X86State::REG_RSP] = NewGuestSP;
  }
  else {
    NewGuestSP -= 4;
    *(uint32_t*)NewGuestSP = ContextBackup->UContextLocation;
    NewGuestSP -= 4;
    *(uint32_t*)NewGuestSP = ContextBackup->SigInfoLocation;
    NewGuestSP -= 4;
    *(uint32_t*)NewGuestSP = ContextBackup->Signal;

    NewGuestSP -= 4;
    *(uint32_t*)NewGuestSP = 0; //FEX_TODO("fix this")
    //LOGMAN_THROW_A_FMT(?? < 0x1'0000'0000ULL, "This needs to be below 4GB");
    Frame->State.gregs[X86State::REG_RSP] = NewGuestSP;
  }

  // The guest starts its signal frame with a zero initialized FPU
  // Set that up now. Little bit costly but it's a requirement
  // This state will be restored on rt_sigreturn
  memset(Frame->State.xmm, 0, sizeof(Frame->State.xmm));
  memset(Frame->State.mm, 0, sizeof(Frame->State.mm));
  Frame->State.FCW = 0x37F;
  Frame->State.FTW = 0xFFFF;

  return true;
}

// FEX_TODO("This is not abi correct wrt linux")
static void doSigRet(FEXCore::Core::CpuStateFrame *Frame, uint64_t AbsoluteLoopTopAddressFillSRA) {
  auto ContextBackup = *(ArchHelpers::Context::ContextBackup **)Frame->State.gregs[X86State::REG_RSP];

  // modifies / replaces the previous stack frames
  memcpy((void*)(Frame->ReturningStackLocation - ContextBackup->HostStackSize), (void*)ContextBackup->HostStackStart, ContextBackup->HostStackSize);

  ucontext_t ucontext;
  _libc_fpstate fp; // FEX_TODO("This is variable sized")
  
  // since we don't fully set it
  memset(&ucontext, 0, sizeof(ucontext));

  // Setup ucontext for restore
  ucontext.uc_mcontext.fpregs = &fp;

  doRestoreThreadState(Frame, &ucontext, ContextBackup, AbsoluteLoopTopAddressFillSRA);

  //ucontext.uc_flags = ?; //FEX_TODO // UC_FP_XSTATE (kernel doesn't check it?), UC_SIGCONTEXT_SS (errors but ingored), UC_STRICT_RESTORE_SS (ignored cus no SC_SS)
  ucontext.uc_link = nullptr;
  //ucontext.uc_stack = ?; //FEX_TODO
  //ucontext.uc_mcontext // restored by RestoreThreadState
  //ucontext.uc_sigmask  // restored by RestoreThreadState
  
  
  __asm__ volatile
  (
    "mov $15, %%rax\n"
    "mov %0, %%rsp\n"
    "syscall \n"
    :
    : "r"(&ucontext)
  );
}

// FEX_TODO("This is not abi correct wrt linux")
void Dispatcher::SigRet(FEXCore::Core::CpuStateFrame *Frame) {
  auto ContextBackup = *(ArchHelpers::Context::ContextBackup **)Frame->State.gregs[X86State::REG_RSP];
  auto NewHostStack = Frame->ReturningStackLocation - ContextBackup->HostStackSize;

  __asm__ volatile
  (
    "mov %0, %%rsp \n"
    "mov %1, %%rdi \n" 
    "mov %2, %%rsi \n"
    "call %P3"
    :
    : "r"(NewHostStack), "r"(Frame), "r"(AbsoluteLoopTopAddressFillSRA), "i"(doSigRet)
  );
}

bool Dispatcher::HandleSIGILL(int Signal, void *info, void *ucontext) {

  /*
  if (ArchHelpers::Context::GetPc(ucontext) == SignalHandlerReturnAddress) {
    RestoreThreadState(ucontext);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --SignalHandlerRefCounter;
    return true;
  }*/

  if (ArchHelpers::Context::GetPc(ucontext) == PauseReturnInstruction) {
    //FEX_TODO("this will crash")
    //RestoreThreadState(ucontext);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --SignalHandlerRefCounter;
    return true;
  }

  return false;
}

bool Dispatcher::HandleSignalPause(int Signal, void *info, void *ucontext) {
  FEXCore::Core::SignalEvent SignalReason = ThreadState->SignalReason.load();
  auto Frame = ThreadState->CurrentFrame;

  if (SignalReason == FEXCore::Core::SignalEvent::Pause) {
    // Store our thread state so we can come back to this
    //FEX_TODO("FIXME");
    //StoreThreadState(Signal, ucontext);

    if (SRAEnabled && IsAddressInJITCode(ArchHelpers::Context::GetPc(ucontext), false)) {
      // We are in jit, SRA must be spilled
      ArchHelpers::Context::SetPc(ucontext, ThreadPauseHandlerAddressSpillSRA);
    } else {
      if (SRAEnabled) {
        // We are in non-jit, SRA is already spilled
        LOGMAN_THROW_A_FMT(!IsAddressInJITCode(ArchHelpers::Context::GetPc(ucontext), true),
                           "Signals in dispatcher have unsynchronized context");
      }
      ArchHelpers::Context::SetPc(ucontext, ThreadPauseHandlerAddress);
    }

    // Set our state register to point to our guest thread data
    ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    ++SignalHandlerRefCounter;

    ThreadState->SignalReason.store(FEXCore::Core::SignalEvent::Nothing);
    return true;
  }

  if (SignalReason == FEXCore::Core::SignalEvent::Stop) {
    // Our thread is stopping
    // We don't care about anything at this point
    // Set the stack to our starting location when we entered the core and get out safely
    ArchHelpers::Context::SetSp(ucontext, Frame->ReturningStackLocation);

    // Our ref counting doesn't matter anymore
    SignalHandlerRefCounter = 0;

    // Set the new PC
    if (SRAEnabled && IsAddressInJITCode(ArchHelpers::Context::GetPc(ucontext), false)) {
      // We are in jit, SRA must be spilled
      ArchHelpers::Context::SetPc(ucontext, ThreadStopHandlerAddressSpillSRA);
    } else {
      if (SRAEnabled) {
        // We are in non-jit, SRA is already spilled
        LOGMAN_THROW_A_FMT(!IsAddressInJITCode(ArchHelpers::Context::GetPc(ucontext), true),
                           "Signals in dispatcher have unsynchronized context");
      }
      ArchHelpers::Context::SetPc(ucontext, ThreadStopHandlerAddress);
    }

    // We need to be a little bit careful here
    // If we were already paused (due to GDB) and we are immediately stopping (due to gdb kill)
    // Then we need to ensure we don't double decrement our idle thread counter
    if (ThreadState->RunningEvents.ThreadSleeping) {
      // If the thread was sleeping then its idle counter was decremented
      // Reincrement it here to not break logic
      ++ThreadState->CTX->IdleWaitRefCount;
    }

    ThreadState->SignalReason.store(FEXCore::Core::SignalEvent::Nothing);
    return true;
  }

  if (SignalReason == FEXCore::Core::SignalEvent::Return) {
    //FEX_TODO("FIXME")
    //RestoreThreadState(ucontext);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --SignalHandlerRefCounter;

    ThreadState->SignalReason.store(FEXCore::Core::SignalEvent::Nothing);
    return true;
  }

  return false;
}

uint64_t Dispatcher::GetCompileBlockPtr() {
  using ClassPtrType = void (FEXCore::Context::Context::*)(FEXCore::Core::CpuStateFrame *, uint64_t);
  union PtrCast {
    ClassPtrType ClassPtr;
    uintptr_t Data;
  };

  PtrCast CompileBlockPtr;
  CompileBlockPtr.ClassPtr = &FEXCore::Context::Context::CompileBlockJit;
  return CompileBlockPtr.Data;
}

void Dispatcher::RemoveCodeBuffer(uint8_t* start_to_remove) {
  for (auto iter = CodeBuffers.begin(); iter != CodeBuffers.end(); ++iter) {
    auto [start, end] = *iter;
    if (start == reinterpret_cast<uint64_t>(start_to_remove)) {
      CodeBuffers.erase(iter);
      return;
    }
  }
}

bool Dispatcher::IsAddressInJITCode(uint64_t Address, bool IncludeDispatcher) const {
  for (auto [start, end] : CodeBuffers) {
    if (Address >= start && Address < end) {
      return true;
    }
  }

  if (IncludeDispatcher && IsAddressInDispatcher(Address)) {
    return true;
  }

  return false;
}

}
