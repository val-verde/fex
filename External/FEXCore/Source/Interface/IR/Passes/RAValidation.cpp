#include "Interface/IR/PassManager.h"
#include "Interface/IR/Passes/IRValidation.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"

#include <FEXCore/IR/IR.h>
#include <FEXCore/IR/IREmitter.h>
#include <FEXCore/IR/IntrusiveIRList.h>
#include <FEXCore/IR/RegisterAllocationData.h>


#include <algorithm>
#include <deque>
#include <unordered_map>

namespace FEXCore::IR::Validation {

struct RegState {
  static constexpr uint32_t UninitializedValue = 0;
  static constexpr uint32_t InvalidReg         = 0xffff'ffff;
  static constexpr uint32_t CorruptedPair      = 0xffff'fffe;
  static constexpr uint32_t ClobberedValue     = 0xffff'fffd;
  static constexpr uint32_t StaticAssigned     = 0xffff'ff00;

  // This class makes some assumptions about how the host registers are arranged and mapped to virtual registers:
  // 1. There will be less than 32 GPRs and 32 FPRs
  // 2. If the GPRFixed class is used, there will be 16 GPRs and 16 FixedGPRs max
  // 3. Same with FPRFixed
  // 4. If the GPRPairClass is used, it is assumed each GPRPair N will map onto GPRs N*2 and N*2 + 1

  // These assumptions were all true for the state of the arm64 and x86 jits at the time this was written

  bool Set(PhysicalRegister Reg, uint32_t ssa) {
    LOGMAN_THROW_A(ssa != 0, "RegState assumes ssa0 will be the block header and never assigned to a register");

    switch (Reg.Class) {
    case GPRClass:
      GPRs[Reg.Reg] = ssa;
      return true;
    case GPRFixedClass:
      // On arm64, there are 16 Fixed and 9 normal
      GPRs[Reg.Reg + 16] = ssa;
      return true;
    case FPRClass:
      FPRs[Reg.Reg] = ssa;
      return true;
    case FPRFixedClass:
      // On arm64, there are 16 Fixed and 12 normal
      FPRs[Reg.Reg + 16] = ssa;
      return true;
    case GPRPairClass:
      if (Reg.Reg <= 16) {
        // Alias paired registers onto both
        GPRs[Reg.Reg*2] = ssa;
        GPRs[Reg.Reg*2 + 1] = ssa;
        return true;
      }
      break;
    }
    return false;
  }

  uint32_t Get(PhysicalRegister Reg) {
    switch (Reg.Class) {
    case GPRClass:
      return GPRs[Reg.Reg];
    case GPRFixedClass:
      if (GPRs[Reg.Reg + 16] == UninitializedValue) {
        return StaticAssigned;
      }
      return GPRs[Reg.Reg + 16];
    case FPRClass:
      return FPRs[Reg.Reg];
    case FPRFixedClass:
      if (FPRs[Reg.Reg + 16] == UninitializedValue) {
        return StaticAssigned;
      }
      return FPRs[Reg.Reg + 16];
    case GPRPairClass:
      if (Reg.Reg > 16)
        break;

      // Make sure both halves of the Pair contain the same SSA
      if (GPRs[Reg.Reg*2] == GPRs[Reg.Reg*2 + 1]) {
        return GPRs[Reg.Reg*2];
      }
      return CorruptedPair;
    }
    return InvalidReg;
  }

  void Intersect(RegState& other) {
    for (size_t i = 0; i < GPRs.size(); i++) {
      if (GPRs[i] != other.GPRs[i]) {
        GPRs[i] = ClobberedValue;
      }
    }

    for (size_t i = 0; i < FPRs.size(); i++) {
      if (FPRs[i] != other.FPRs[i]) {
        FPRs[i] = ClobberedValue;
      }
    }
  }

  void Filter(uint32_t MaxSSA) {
    for (auto &gpr : GPRs) {
      if (gpr > MaxSSA) {
        gpr = ClobberedValue;
      }
    }

    for (auto &fpr : FPRs) {
      if (fpr > MaxSSA) {
        fpr = ClobberedValue;
      }
    }
  }

private:
  std::array<uint32_t, 32> GPRs = {};
  std::array<uint32_t, 32> FPRs = {};

public:
  uint32_t Version{};
};

class RAValidation final : public FEXCore::IR::Pass {
public:
  ~RAValidation() {}
  bool Run(IREmitter *IREmit) override;

private:
  std::unordered_map<uint32_t, RegState> BlockExitState;
  std::deque<OrderedNode*> BlocksToVisit;
};


bool RAValidation::Run(IREmitter *IREmit) {
  if (!Manager->HasPass("RA")) return false;

  IR::RegisterAllocationData* RAData = Manager->GetPass<IR::RegisterAllocationPass>("RA")->GetAllocationData();
  BlockExitState.clear();

  // Get the control flow graph from the validation pass
  auto ValidationPass = Manager->GetPass<IRValidation>("IRValidation");
  LOGMAN_THROW_A(ValidationPass != nullptr, "Couldn't find IRValidation pass");

  auto& OffsetToBlockMap = ValidationPass->OffsetToBlockMap;

  LOGMAN_THROW_A(ValidationPass->EntryBlock != nullptr, "No entry point");
  BlocksToVisit.push_front(ValidationPass->EntryBlock); // Currently only a single entry point

  bool HadError = false;
  std::ostringstream Errors;

  auto CurrentIR = IREmit->ViewIR();
  uint32_t CurrentVersion = 1; // Incremented every backwards edge

  while (!BlocksToVisit.empty())
  {
    auto BlockNode = BlocksToVisit.front();
    uint32_t BlockID = CurrentIR.GetID(BlockNode);
    auto& BlockInfo = OffsetToBlockMap[BlockID];

    auto IsFowardsEdge = [&] (uint32_t PredecessorID) {
      // TODO: This isn't the best definition of fowards/backwards edges. It's possible for
      //       Blocks to be out of order. Will need a proper CFG analysis pass.
      //
      // But I don't think we currently generate Backwards branches that don't follow this rule
      return PredecessorID < BlockID;
    };

    // First, make sure we have the exit state data for all Predecessor
    bool MissingPredecessor = false;

    for (auto Predecessor : BlockInfo.Predecessors) {
      auto PredecessorID = CurrentIR.GetID(Predecessor);
      bool HaveState = BlockExitState.contains(PredecessorID) && BlockExitState[PredecessorID].Version == CurrentVersion;

      if (IsFowardsEdge(PredecessorID) && !HaveState) {
        // We are probably about to visit this node anyway, remove it
        std::remove(BlocksToVisit.begin(), BlocksToVisit.end(), Predecessor);

        // Add the missing predecessor to start of queue
        BlocksToVisit.push_front(Predecessor);
        MissingPredecessor = true;
      }
    }

    if (MissingPredecessor) {
      // We'll have to come back to this block later
      continue;
    }

    // Remove block from queue
    BlocksToVisit.pop_front();

    bool FirstVisit = !BlockExitState.contains(BlockID);

    // Second, we need to determine the register status as of Block entry
    auto BlockOp = CurrentIR.GetOp<IROp_CodeBlock>(BlockNode);
    uint32_t FirstSSA = BlockOp->Begin.ID();

    auto& BlockRegState = BlockExitState.try_emplace(BlockID).first->second;
    bool EmptyRegState = true;
    auto Intersect = [&] (RegState& Other) {
      if (EmptyRegState) {
        BlockRegState = Other;
        EmptyRegState = false;
      } else {
        BlockRegState.Intersect(Other);
      }
    };

    for (auto Predecessor : BlockInfo.Predecessors) {
      auto PredecessorID = CurrentIR.GetID(Predecessor);
      if (BlockExitState.contains(PredecessorID)) {
        if (IsFowardsEdge(PredecessorID)) {
          Intersect(BlockExitState[PredecessorID]);
        } else {
          RegState Filtered = BlockExitState[PredecessorID];
          Filtered.Filter(FirstSSA);
          Intersect(Filtered);
        }
      }
    }

    // Thrid, we need to iterate over all IR ops in the block

    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      uint32_t ID = CurrentIR.GetID(CodeNode);

      // And check that all args point at the correct SSA
      uint8_t NumArgs = IR::GetArgs(IROp->Op);
      for (uint32_t i = 0; i < NumArgs; ++i) {
        OrderedNodeWrapper Arg = IROp->Args[i];

        const auto PhyReg = RAData->GetNodeRegister(Arg.ID());

        if (PhyReg.IsInvalid())
          continue;

        auto CurrentSSAAtReg = BlockRegState.Get(PhyReg);
        if (CurrentSSAAtReg == RegState::InvalidReg) {
          HadError |= true;
          Errors << fmt::format("%ssa{}: Arg[{}] unknown Reg: {}, class: {}\n", ID, i, PhyReg.Reg, PhyReg.Class);
        } else if (CurrentSSAAtReg == RegState::CorruptedPair) {
          HadError |= true;

          auto Lower = BlockRegState.Get(PhysicalRegister(GPRClass, uint8_t(PhyReg.Reg*2) + 1));
          auto Upper = BlockRegState.Get(PhysicalRegister(GPRClass, PhyReg.Reg*2 + 1));

          Errors << fmt::format("%ssa{}: Arg[{}] expects paired reg{} to contain %ssa{}, but it actually contains {{%ssa{}, %ssa{}}}\n",
                                  ID, i, PhyReg.Reg, Arg.ID(), Lower, Upper);
        } else if (CurrentSSAAtReg == RegState::UninitializedValue) {
          HadError |= true;

          Errors << fmt::format("%ssa{}: Arg[{}] expects reg{} to contain %ssa{}, but it is uninitialized\n",
                                ID, i, PhyReg.Reg, Arg.ID());
        } else if (CurrentSSAAtReg == RegState::ClobberedValue) {
          HadError |= true;

          Errors << fmt::format("%ssa{}: Arg[{}] expects reg{} to contain %ssa{}, but contents vary depending on control flow\n",
                                ID, i, PhyReg.Reg, Arg.ID());
        } else if (CurrentSSAAtReg != Arg.ID()) {
          HadError |= true;
          Errors << fmt::format("%ssa{}: Arg[{}] expects reg{} to contain %ssa{}, but it actually contains %ssa{}\n",
                                ID, i, PhyReg.Reg, Arg.ID(), CurrentSSAAtReg);
        }
      }

      // Update BlockState map
      BlockRegState.Set(RAData->GetNodeRegister(ID), ID);
    }

    // Forth, Add successors to the queue of blocks to validate
    for (auto Successor : BlockInfo.Successors) {
      auto SuccessorID = CurrentIR.GetID(Successor);

      // TODO: This isn't the best definition of fowards/backwards edges. It's possible for
      //       Blocks to be out of order. Will need a proper CFG analysis pass.
      //
      // But I don't think we currently generate Backwards branches that don't follow this rule
      bool FowardsEdge = SuccessorID > BlockID;

      if (FowardsEdge) {
        // Always follow forwards edges, assuming it's not already on the queue
        if (std::find(BlocksToVisit.begin(), BlocksToVisit.end(), Successor) == std::end(BlocksToVisit)) {
          // Push to the back of queue so there is a higher chance all predecessors for this block are done first
          BlocksToVisit.push_back(Successor);
        }
      } else if (FirstVisit) {
        // Now that we have the block data for the backwards edge, we can visit it again and make
        // sure it (and all it's successors) are still valid.

        // But only do this the first time we encounter each backwards edge.

        // Push to the front of queue, so we get this re-checking done before examining future nodes.
        BlocksToVisit.push_front(Successor);

        // Make sure states are reprocessed
        CurrentVersion++;
      }
    }

    BlockRegState.Version = CurrentVersion;

    if (CurrentVersion > 10000) {
      Errors << "Infinite Loop\n";
      HadError |= true;

      for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
        uint32_t BlockID = CurrentIR.GetID(BlockNode);
        auto& BlockInfo = OffsetToBlockMap[BlockID];

        Errors << fmt::format("Block {}\n\tPredecessors: ", BlockID);

        for (auto Predecessor : BlockInfo.Predecessors) {
          auto PredecessorID = CurrentIR.GetID(Predecessor);
          bool FowardsEdge = PredecessorID < BlockID;
          if (!FowardsEdge) {
            Errors << "(Backwards): ";
          }
          Errors << fmt::format("Block {} ", PredecessorID);
        }

        Errors << "\n\tSuccessors: ";

        for (auto Successor : BlockInfo.Successors) {
          auto SuccessorID = CurrentIR.GetID(Successor);
          bool FowardsEdge = SuccessorID > BlockID;

          if (!FowardsEdge) {
            Errors << "(Backwards): ";
          }
          Errors << fmt::format("Block {} ", SuccessorID);

        }

        Errors << "\n\n";
      }

      break;
    }

  }

  if (HadError) {
    std::stringstream IrDump;
    FEXCore::IR::Dump(&IrDump, &CurrentIR, RAData);

    LogMan::Msg::EFmt("RA Validation Error\n{}\nErrors:\n{}\n", IrDump.str(), Errors.str());

    LOGMAN_MSG_A("Encountered RA validation Error");

    Errors.clear();
  }

  return false;
}

std::unique_ptr<FEXCore::IR::Pass> CreateRAValidation() {
  return std::make_unique<RAValidation>();
}
}
