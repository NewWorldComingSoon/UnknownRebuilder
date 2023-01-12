
#include <unknown/Target/Target.h>

#include "x86/Target.x86.h"
#include "arm/Target.arm.h"

namespace unknown {

////////////////////////////////////////////////////////////////////////////////////////
//// Function
std::unique_ptr<Target>
CreateTargetForX86()
{
    return {};
}

} // namespace unknown
