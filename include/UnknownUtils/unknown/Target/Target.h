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

public:
    Target() = default;
    virtual ~Target() = default;

public:
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) = 0;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) = 0;
};

////////////////////////////////////////////////////////////////////////////////////////
//// Function
std::unique_ptr<Target>
CreateTargetForX86();

} // namespace unknown