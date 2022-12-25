#pragma once
#include <UnknownIR/InstructionBase.h>
#include <UnknownIR/Constant.h>

namespace uir {

class BasicBlock;

class JccAddrInstruction : public TerminatorInstruction
{
public:
    JccAddrInstruction();
    virtual ~JccAddrInstruction();
};

class JccBBInstruction : public TerminatorInstruction
{
public:
    JccBBInstruction();
    virtual ~JccBBInstruction();
};

} // namespace uir
