#include "Target.arm.h"

namespace unknown {

TargetARM::TargetARM(uint32_t ModeBits) : Target(ModeBits)
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

// Get the register type bits by register id
uint32_t
TargetARM::getRegisterTypeBits(uint32_t RegID)
{
    // TODO
    return 0;
}

// Get carry register
uint32_t
TargetARM::getCarryRegister()
{
    // TODO
    return 0;
}

} // namespace unknown
