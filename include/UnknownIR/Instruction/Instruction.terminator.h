#pragma once
#include <UnknownIR/InstructionBase.h>
#include <UnknownIR/Constant.h>

namespace uir {

class TerminatorInst : public Instruction
{
protected:
    TerminatorInst(OpCodeID OpCodeId);
    virtual ~TerminatorInst();

public:
};

} // namespace uir
