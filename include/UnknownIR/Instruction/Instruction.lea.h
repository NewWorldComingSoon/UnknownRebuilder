#pragma once
#include <UnknownIR/InstructionBase.h>

namespace uir {

class LeaInstruction : public Instruction
{
public:
    explicit LeaInstruction(Value *Val, Value *Ptr, bool IsVolatile = false);
    virtual ~LeaInstruction();
};

} // namespace uir
