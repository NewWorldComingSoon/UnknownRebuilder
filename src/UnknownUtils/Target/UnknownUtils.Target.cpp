
#include <unknown/Target/Target.h>

#include "x86/Target.x86.h"
#include "arm/Target.arm.h"

namespace unknown {

////////////////////////////////////////////////////////////////////////////////////////
//// Function
std::unique_ptr<Target>
CreateTargetForX86(uint32_t ModeBits)
{
    return std::make_unique<TargetX86>(ModeBits);
}

std::unique_ptr<Target>
CreateTargetForARM(uint32_t ModeBits)
{
    return std::make_unique<TargetARM>(ModeBits);
}

} // namespace unknown
