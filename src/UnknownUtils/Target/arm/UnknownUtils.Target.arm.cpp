#include "Target.arm.h"

namespace unknown {

TargetARM::TargetARM()
{
    //
}

TargetARM::~TargetARM()
{
    //
}

// Get the register name by register id
std::string
TargetARM::getRegisterName(uint32_t RegID)
{
    // TODO
    return "";
}

// Get the register id by register name
uint32_t
TargetARM::getRegisterID(const std::string &RegName)
{
    // TODO
    return 0;
}

} // namespace unknown
