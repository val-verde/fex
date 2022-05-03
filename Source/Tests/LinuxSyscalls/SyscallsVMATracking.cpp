/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: VMA Tracking
$end_info$
*/

#include "Tests/LinuxSyscalls/Syscalls.h"

namespace FEX::HLE {

/// List Operations ///

inline void SyscallHandler::VMATracking::ListCheckVMALinks(VMAEntry *VMA) {
  if (VMA) {
    LOGMAN_THROW_A_FMT(VMA->ResourceNextVMA != VMA, "VMA tracking error");
    LOGMAN_THROW_A_FMT(VMA->ResourcePrevVMA != VMA, "VMA tracking error");
  }
}

// Removes a VMA from corresponding MappedResource list
// Returns true if list is empty
bool SyscallHandler::VMATracking::ListRemove(VMAEntry *VMA) {
  LOGMAN_THROW_A_FMT(VMA->Resource != nullptr, "VMA tracking error");

  // if it has prev, make prev to next
  if (VMA->ResourcePrevVMA) {
    LOGMAN_THROW_A_FMT(VMA->ResourcePrevVMA->ResourceNextVMA == VMA, "VMA tracking error");
    VMA->ResourcePrevVMA->ResourceNextVMA = VMA->ResourceNextVMA;
  } else {
    LOGMAN_THROW_A_FMT(VMA->Resource->FirstVMA == VMA, "VMA tracking error");
  }

  // if it has next, make next to prev
  if (VMA->ResourceNextVMA) {
    LOGMAN_THROW_A_FMT(VMA->ResourceNextVMA->ResourcePrevVMA == VMA, "VMA tracking error");
    VMA->ResourceNextVMA->ResourcePrevVMA = VMA->ResourcePrevVMA;
  }

  // If it is the first in the list, make Next the first in the list
  if (VMA->Resource && VMA->Resource->FirstVMA == VMA) {
    LOGMAN_THROW_A_FMT(!VMA->ResourceNextVMA || VMA->ResourceNextVMA->ResourcePrevVMA == nullptr, "VMA tracking error");

    VMA->Resource->FirstVMA = VMA->ResourceNextVMA;
  }

  ListCheckVMALinks(VMA);
  ListCheckVMALinks(VMA->ResourceNextVMA);
  ListCheckVMALinks(VMA->ResourcePrevVMA);

  // Return true if list is empty
  return VMA->Resource->FirstVMA == nullptr;
}

// Replaces a VMA in corresponding MappedResource list
// Requires NewVMA->Resource, NewVMA->ResourcePrevVMA and NewVMA->ResourceNextVMA to be already setup
void SyscallHandler::VMATracking::ListReplace(VMAEntry *VMA, VMAEntry *NewVMA) {
  LOGMAN_THROW_A_FMT(VMA->Resource != nullptr, "VMA tracking error");

  LOGMAN_THROW_A_FMT(VMA->Resource == NewVMA->Resource, "VMA tracking error");
  LOGMAN_THROW_A_FMT(NewVMA->ResourcePrevVMA == VMA->ResourcePrevVMA, "VMA tracking error");
  LOGMAN_THROW_A_FMT(NewVMA->ResourceNextVMA == VMA->ResourceNextVMA, "VMA tracking error");

  if (VMA->ResourcePrevVMA) {
    LOGMAN_THROW_A_FMT(VMA->Resource->FirstVMA != VMA, "VMA tracking error");
    LOGMAN_THROW_A_FMT(VMA->ResourcePrevVMA->ResourceNextVMA == VMA, "VMA tracking error");
    VMA->ResourcePrevVMA->ResourceNextVMA = NewVMA;
  } else {
    LOGMAN_THROW_A_FMT(VMA->Resource->FirstVMA == VMA, "VMA tracking error");
    VMA->Resource->FirstVMA = NewVMA;
  }

  if (VMA->ResourceNextVMA) {
    LOGMAN_THROW_A_FMT(VMA->ResourceNextVMA->ResourcePrevVMA == VMA, "VMA tracking error");
    VMA->ResourceNextVMA->ResourcePrevVMA = NewVMA;
  }

  ListCheckVMALinks(VMA);
  ListCheckVMALinks(NewVMA);
  ListCheckVMALinks(VMA->ResourceNextVMA);
  ListCheckVMALinks(VMA->ResourcePrevVMA);
}

// Inserts a VMA in corresponding MappedResource list
// Requires NewVMA->Resource, NewVMA->ResourcePrevVMA and NewVMA->ResourceNextVMA to be already setup
void SyscallHandler::VMATracking::ListInsert(VMAEntry *AfterVMA, VMAEntry *NewVMA) {
  LOGMAN_THROW_A_FMT(NewVMA->Resource != nullptr, "VMA tracking error");

  LOGMAN_THROW_A_FMT(AfterVMA->Resource == NewVMA->Resource, "VMA tracking error");
  LOGMAN_THROW_A_FMT(NewVMA->ResourcePrevVMA == AfterVMA, "VMA tracking error");
  LOGMAN_THROW_A_FMT(NewVMA->ResourceNextVMA == AfterVMA->ResourceNextVMA, "VMA tracking error");

  if (AfterVMA->ResourceNextVMA) {
    LOGMAN_THROW_A_FMT(AfterVMA->ResourceNextVMA->ResourcePrevVMA == AfterVMA, "VMA tracking error");
    AfterVMA->ResourceNextVMA->ResourcePrevVMA = NewVMA;
  }
  AfterVMA->ResourceNextVMA = NewVMA;

  ListCheckVMALinks(AfterVMA);
  ListCheckVMALinks(NewVMA);
  ListCheckVMALinks(AfterVMA->ResourceNextVMA);
  ListCheckVMALinks(AfterVMA->ResourcePrevVMA);
}

// Prepends a VMA
// Requires NewVMA->Resource, NewVMA->ResourcePrevVMA and NewVMA->ResourceNextVMA to be already setup
void SyscallHandler::VMATracking::ListPrepend(MappedResource *Resource, VMAEntry *NewVMA) {
  LOGMAN_THROW_A_FMT(Resource != nullptr, "VMA tracking error");

  LOGMAN_THROW_A_FMT(NewVMA->Resource == Resource, "VMA tracking error");
  LOGMAN_THROW_A_FMT(NewVMA->ResourcePrevVMA == nullptr, "VMA tracking error");
  LOGMAN_THROW_A_FMT(NewVMA->ResourceNextVMA == Resource->FirstVMA, "VMA tracking error");

  if (Resource->FirstVMA) {
    LOGMAN_THROW_A_FMT(Resource->FirstVMA->ResourcePrevVMA == nullptr, "VMA tracking error");
    Resource->FirstVMA->ResourcePrevVMA = NewVMA;
  }

  Resource->FirstVMA = NewVMA;

  ListCheckVMALinks(NewVMA);
  ListCheckVMALinks(NewVMA->ResourceNextVMA);
  ListCheckVMALinks(NewVMA->ResourcePrevVMA);
}

/// VMA tracking ///

// Lookup a VMA by address
SyscallHandler::VMATracking::VMAsType::const_iterator SyscallHandler::VMATracking::LookupVMAUnsafe(uint64_t GuestAddr) const {
  auto Entry = VMAs.upper_bound(GuestAddr);

  if (Entry != VMAs.begin()) {
    --Entry;

    if (Entry->first <= GuestAddr && (Entry->first + Entry->second.Length) > GuestAddr) {
      return Entry;
    }
  }

  return VMAs.end();
}

// Set or Replace mappings in a range with a new mapping
void SyscallHandler::VMATracking::SetUnsafe(FEXCore::Context::Context *CTX, MappedResource *MappedResource, uintptr_t Base,
                                            uintptr_t Offset, uintptr_t Length, VMAOptions Flags) {
  ClearUnsafe(CTX, Base, Length, MappedResource);

  auto VMAInserted = VMAs.emplace(
      Base, VMAEntry{MappedResource, nullptr, MappedResource ? MappedResource->FirstVMA : nullptr, Base, Offset, Length, Flags});
  LOGMAN_THROW_A_FMT(VMAInserted.second == true, "VMA Tracking corruption");

  if (MappedResource) {
    // Insert to the front of the linked list
    ListPrepend(MappedResource, &VMAInserted.first->second);
  }
}

// XXX this is preliminary and will get rechecked & cleaned up
// Remove mappings in a range, freeing their associated MappedResource, unless it is equal to PreservedMappedResource
void SyscallHandler::VMATracking::ClearUnsafe(FEXCore::Context::Context *CTX, uintptr_t Base, uintptr_t Length,
                                              MappedResource *PreservedMappedResource) {
  const auto Top = Base + Length;

  // find the first Mapping at or after the Range ends, or ::end()
  // Top is the address after the end
  auto MappingIter = VMAs.lower_bound(Top);

  // Iterate backwards all mappings
  while (MappingIter != VMAs.begin()) {
    MappingIter--;

    const auto Mapping = &MappingIter->second;
    const auto MapBase = MappingIter->first;
    const auto MapTop = MapBase + Mapping->Length;

    if (MapTop <= Base) {
      // Mapping ends before the Range start, exit
      break;
    } else if (MapBase < Base && MapTop <= Top) {
      // Mapping starts before Range & ends at or before Range, trim end
      Mapping->Length = Base - MapBase;
    } else if (MapBase < Base && MapTop > Top) {
      // Mapping starts before Range & ends after Range, split

      // trim first half
      Mapping->Length = Base - MapBase;

      // insert second half, link it after Mapping
      auto NewOffset = Mapping->Offset + MapBase + Length;
      auto NewLength = MapTop - Top;

      auto Inserted =
          VMAs.emplace(Top, VMAEntry{Mapping->Resource, Mapping, Mapping->ResourceNextVMA, Top, NewOffset, NewLength, Mapping->Flags});
      LOGMAN_THROW_A_FMT(Inserted.second, "VMA tracking error");
      if (Mapping->Resource) {
        ListInsert(Mapping, &Inserted.first->second);
      }
    } else if (MapBase >= Base && MapTop <= Top) {
      // Mapping is included or equal to Range, delete
      // returns next element, so -- is safe at loop

      // If linked to a Mapped Resource, remove from linked list and possibly delete the Mapped Resource
      if (Mapping->Resource) {
        if (ListRemove(Mapping) && Mapping->Resource != PreservedMappedResource) {
          if (Mapping->Resource->AOTIRCacheEntry) {
            FEXCore::Context::UnloadAOTIRCacheEntry(CTX, Mapping->Resource->AOTIRCacheEntry);
          }
          MappedResources.erase(Mapping->Resource->Iterator);
        }
      }

      // remove
      MappingIter = VMAs.erase(MappingIter);
    } else if (MapBase >= Base && MapTop > Top) {
      // Mapping starts after or at Range && ends after Range, trim start

      auto NewOffset = Mapping->Offset + MapBase + Length;
      auto NewLength = MapTop - Top;
      // insert second half
      // Link it as a replacement to Mapping
      auto Inserted = VMAs.emplace(
          Top, VMAEntry{Mapping->Resource, Mapping->ResourcePrevVMA, Mapping->ResourceNextVMA, Top, NewOffset, NewLength, Mapping->Flags});
      LOGMAN_THROW_A_FMT(Inserted.second, "VMA tracking error");

      // If linked to a Mapped Resource, remove from linked list
      if (Mapping->Resource) {
        ListReplace(Mapping, &Inserted.first->second);
      }

      // erase original
      // returns next element, so it can be decremented safely in the next loop iteration
      MappingIter = VMAs.erase(MappingIter);
    } else {
      ERROR_AND_DIE_FMT("Invalid Case");
    }
  }
}

// XXX this is preliminary and will get rechecked & cleaned up
// Change flags of mappings in a range and split the mappings if needed
void SyscallHandler::VMATracking::ChangeUnsafe(uintptr_t Base, uintptr_t Length, VMAProt Prot) {
  const auto Top = Base + Length;

  // find the first Mapping at or after the Range ends, or ::end()
  // Top is the address after the end
  auto MappingIter = VMAs.lower_bound(Top);

  // Iterate backwards all mappings
  while (MappingIter != VMAs.begin()) {
    MappingIter--;

    const auto Mapping = &MappingIter->second;
    const auto MapBase = MappingIter->first;
    const auto MapTop = MapBase + Mapping->Length;

    if (MapTop <= Base) {
      // Mapping ends before the Range start, exit
      break;
    } else if (Mapping->Flags.Prot == Prot) {
      continue;
    } else if (MapBase < Base && MapTop <= Top) {
      // Mapping starts before Range & ends at or before Range, split second half

      // Trim end of original mapping
      Mapping->Length = Base - MapBase;

      // Make new VMA with new flags, insert remaining of the original mapping
      auto NewOffset = Mapping->Offset + Mapping->Length;
      auto NewLength = Top - Base;
      auto NewFlags = Mapping->Flags;
      NewFlags.Prot = Prot;

      auto Inserted =
          VMAs.emplace(Base, VMAEntry{Mapping->Resource, Mapping, Mapping->ResourceNextVMA, Base, NewOffset, NewLength, NewFlags});
      LOGMAN_THROW_A_FMT(Inserted.second, "VMA tracking error");
      if (Mapping->Resource) {
        ListInsert(Mapping, &Inserted.first->second);
      }
    } else if (MapBase < Base && MapTop > Top) {
      // Mapping starts before Range & ends after Range, split twice

      // Trim end of original mapping
      Mapping->Length = Base - MapBase;

      // Make new VMA with new flags, insert for length of mapping
      auto NewOffset1 = Mapping->Offset + Mapping->Length;
      auto NewLength1 = Top - Base;
      auto NewFlags1 = Mapping->Flags;
      NewFlags1.Prot = Prot;

      auto Inserted1 =
          VMAs.emplace(Base, VMAEntry{Mapping->Resource, Mapping, Mapping->ResourceNextVMA, Base, NewOffset1, NewLength1, NewFlags1});
      LOGMAN_THROW_A_FMT(Inserted1.second, "VMA tracking error");
      auto Mapping1 = &Inserted1.first->second;

      if (Mapping->Resource) {
        ListInsert(Mapping, Mapping1);
      }

      // Insert the rest of the mapping with original flags

      // Make new VMA with new flags, insert for length of mapping
      auto NewOffset2 = Mapping1->Offset + Mapping1->Length;
      auto NewLength2 = MapTop - Top;

      auto Inserted2 =
          VMAs.emplace(Top, VMAEntry{Mapping->Resource, Mapping1, Mapping1->ResourceNextVMA, Top, NewOffset2, NewLength2, Mapping->Flags});
      LOGMAN_THROW_A_FMT(Inserted2.second, "VMA tracking error");
      if (Mapping->Resource) {
        ListInsert(Mapping1, &Inserted2.first->second);
      }
    } else if (MapBase >= Base && MapTop <= Top) {
      // Mapping fully contained
      // Just update flags

      Mapping->Flags.Prot = Prot;
    } else if (MapBase >= Base && MapTop > Top) {
      // Mapping starts after or at Range && ends after Range

      auto MapFlags = Mapping->Flags;

      // Trim start, update flags
      Mapping->Length = Top - MapBase;
      Mapping->Flags.Prot = Prot;

      auto NewOffset = Mapping->Offset + Mapping->Length;
      auto NewLength = MapTop - Top;

      // insert second part with original flags
      // Link it as a replacement to Mapping
      auto Inserted =
          VMAs.emplace(Top, VMAEntry{Mapping->Resource, Mapping, Mapping->ResourceNextVMA, Top, NewOffset, NewLength, MapFlags});
      LOGMAN_THROW_A_FMT(Inserted.second, "VMA tracking error");
      if (Mapping->Resource) {
        ListInsert(Mapping, &Inserted.first->second);
      }
    } else {
      ERROR_AND_DIE_FMT("Invalid Case");
    }
  }
}

// This matches the peculiarities algorithm used in linux ksys_shmdt (linux kernel 5.16, ipc/shm.c)
uintptr_t SyscallHandler::VMATracking::ClearShmUnsafe(FEXCore::Context::Context *CTX, uintptr_t Base) {
  auto Entry = VMAs.upper_bound(Base);

  if (Entry != VMAs.begin()) {
    --Entry;

    do {
      if (Entry->second.Base - Base == Entry->second.Offset && Entry->second.Resource &&
          Entry->second.Resource->Iterator->first.dev == MRID_SHM) {

        const auto ShmLength = Entry->second.Resource->Iterator->second.Length;
        const auto Resource = Entry->second.Resource;

        do {
          if (Entry->second.Resource == Resource) {
            if (ListRemove(&Entry->second)) {
              if (Entry->second.Resource->AOTIRCacheEntry) {
                FEXCore::Context::UnloadAOTIRCacheEntry(CTX, Entry->second.Resource->AOTIRCacheEntry);
              }
              MappedResources.erase(Entry->second.Resource->Iterator);
            }
            Entry = VMAs.erase(Entry);
          } else {
            Entry++;
          }

        } while (Entry != VMAs.end() && (Entry->second.Base + Entry->second.Length - Base) <= ShmLength);

        return ShmLength;
      }
    } while (++Entry != VMAs.end());
  }

  return 0;
}
}