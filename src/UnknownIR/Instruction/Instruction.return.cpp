#pragma once
#include <Instruction.h>

namespace uir {
////////////////////////////////////////////////////////////
//     ReturnInst
//
ReturnInst::ReturnInst() : Instruction(OpCodeID::Ret)
{
    //
}

ReturnInst::~ReturnInst()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
ReturnInst::getOpcodeName() const
{
    return RetComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
ReturnInst::getDefaultNumberOfOperands() const
{
    return RetComponent.mNumberOfOperands;
}

// Is this instruction with flags?
bool
ReturnInst::hasFlags() const
{
    return RetComponent.mHasFlags;
}

////////////////////////////////////////////////////////////
// Static
ReturnInst *
ReturnInst::get()
{
    return new ReturnInst();
}

////////////////////////////////////////////////////////////
//     ReturnImmInst
//
ReturnImmInst::ReturnImmInst(ConstantInt *ImmConstantInt) : Instruction(OpCodeID::RetIMM)
{
    // Insert ImmConstantInt   -> op1
    insertOperandAndUpdateUsers(ImmConstantInt);
}

ReturnImmInst::~ReturnImmInst()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
ReturnImmInst::getOpcodeName() const
{
    return RetIMMComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
ReturnImmInst::getDefaultNumberOfOperands() const
{
    return RetIMMComponent.mNumberOfOperands;
}

// Is this instruction with flags?
bool
ReturnImmInst::hasFlags() const
{
    return RetIMMComponent.mHasFlags;
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the immediate constant int
const ConstantInt *
ReturnImmInst::getImmConstantInt() const
{
    return dynamic_cast<const ConstantInt *>(getOperand(0));
}

// Set the immediate constant int
void
ReturnImmInst::setImmConstantInt(ConstantInt *ImmConstantInt)
{
    setOperandAndUpdateUsers(0, ImmConstantInt);
}

////////////////////////////////////////////////////////////
// Static
ReturnImmInst *
ReturnImmInst::get(ConstantInt *ImmConstantInt)
{
    return new ReturnImmInst(ImmConstantInt);
}

} // namespace uir
