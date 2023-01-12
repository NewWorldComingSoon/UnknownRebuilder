#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>

#include "unknown/ADT/StringRef.h"

namespace unknown {

class Target
{
protected:
    std::unordered_map<uint32_t, std::string> mReg2Name;
    std::unordered_map<std::string, uint32_t> mName2Reg;
    uint32_t mModeBit;

public:
    explicit Target(uint32_t ModeBits) : mModeBit(ModeBits) {}
    virtual ~Target() = default;

public:
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) = 0;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) = 0;

    // Get carry register
    virtual uint32_t getCarryRegister() = 0;
};

////////////////////////////////////////////////////////////////////////////////////////
//// Function
std::unique_ptr<Target>
CreateTargetForX86(uint32_t ModeBits = 64);

std::unique_ptr<Target>
CreateTargetForARM(uint32_t ModeBits = 64);

} // namespace unknown