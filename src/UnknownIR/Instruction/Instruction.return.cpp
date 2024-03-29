#include <Instruction.h>

#include <unknown/ADT/StringExtras.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {
////////////////////////////////////////////////////////////
//     ReturnInstruction
//
ReturnInstruction::ReturnInstruction(Context &C) : TerminatorInstruction(C, OpCodeID::Ret)
{
    //
}

ReturnInstruction::~ReturnInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
ReturnInstruction::getOpcodeName() const
{
    return RetComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
ReturnInstruction::getDefaultNumberOfOperands() const
{
    return RetComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
ReturnInstruction::hasResult() const
{
    return RetComponent.mHasResult;
}

// Is this instruction with flags?
bool
ReturnInstruction::hasFlags() const
{
    return RetComponent.mHasFlags;
}

// Print the instruction
void
ReturnInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
}

////////////////////////////////////////////////////////////
// Static
ReturnInstruction *
ReturnInstruction::get(Context &C)
{
    return new ReturnInstruction(C);
}

////////////////////////////////////////////////////////////
//     ReturnImmInstruction
//
ReturnImmInstruction::ReturnImmInstruction(Context &C, ConstantInt *ImmConstantInt) :
    TerminatorInstruction(C, OpCodeID::RetIMM)
{
    // Insert ImmConstantInt   -> op1
    insertOperandAndUpdateUsers(ImmConstantInt);
}

ReturnImmInstruction::~ReturnImmInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
ReturnImmInstruction::getOpcodeName() const
{
    return RetIMMComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
ReturnImmInstruction::getDefaultNumberOfOperands() const
{
    return RetIMMComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
ReturnImmInstruction::hasResult() const
{
    return RetIMMComponent.mHasResult;
}

// Is this instruction with flags?
bool
ReturnImmInstruction::hasFlags() const
{
    return RetIMMComponent.mHasFlags;
}

// Print the instruction
void
ReturnImmInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
    OS << UIR_OPCODE_SEPARATOR;
    OS << getImmConstantInt()->getReadableName();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the immediate constant int
const ConstantInt *
ReturnImmInstruction::getImmConstantInt() const
{
    return dynamic_cast<const ConstantInt *>(getOperand(0));
}

// Set the immediate constant int
void
ReturnImmInstruction::setImmConstantInt(ConstantInt *ImmConstantInt)
{
    setOperandAndUpdateUsers(0, ImmConstantInt);
}

////////////////////////////////////////////////////////////
// Static
ReturnImmInstruction *
ReturnImmInstruction::get(Context &C, ConstantInt *ImmConstantInt)
{
    return new ReturnImmInstruction(C, ImmConstantInt);
}

} // namespace uir
