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

// Get the register parent id by register id
uint32_t
TargetARM::getRegisterParentID(uint32_t RegID)
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

// Is the register type low 8 bits?
bool
TargetARM::IsRegisterTypeLow8Bits(uint32_t RegID)
{
    // TODO
    return false;
}

// Is the register type high 8 bits?
bool
TargetARM::IsRegisterTypeHigh8Bits(uint32_t RegID)
{
    // TODO
    return false;
}

// Get carry register
uint32_t
TargetARM::getCarryRegister()
{
    // TODO
    return 0;
}

} // namespace unknown
