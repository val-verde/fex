#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

namespace FEXCore {
class JITSymbols final {
public:
  JITSymbols();
  ~JITSymbols();
  void Register(void *HostAddr, uint64_t GuestAddr, uint32_t CodeSize, const std::string& Name);
private:
  FILE* fp{};
};
}
