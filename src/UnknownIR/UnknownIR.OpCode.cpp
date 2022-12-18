
#include <cassert>

#include <OpCode.h>

namespace uir {

////////////////////////////////////////////////////////////////////
// Function
// Get OpCode component by ID
const OpCodeComponent &
getOpCodeComponent(OpCodeID ID)
{
    for (const auto &OpCodeComponent : GlobalOpCodeComponents)
    {
        if (OpCodeComponent.mOpCodeID == ID)
        {
            return OpCodeComponent;
        }
    }

    assert(false && "OpCodeID is not found");
    return GlobalOpCodeComponents[0];
}

// Get OpCode component by name
const OpCodeComponent &
getOpCodeComponent(const char *Name)
{
    assert(Name != nullptr && "Name == nullptr");

    for (const auto &OpCodeComponent : GlobalOpCodeComponents)
    {
        if (OpCodeComponent.mOpCodeName.compare(Name) == 0)
        {
            return OpCodeComponent;
        }
    }

    assert(false && "OpCodeName is not found");
    return GlobalOpCodeComponents[0];
}

} // namespace uir