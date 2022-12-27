#include <Instruction.h>

#include <unknown/ADT/StringExtras.h>

namespace uir {
////////////////////////////////////////////////////////////
//     ReturnInstruction
//
ReturnInstruction::ReturnInstruction() : TerminatorInstruction(OpCodeID::Ret)
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

// Is this instruction with flags?
bool
ReturnInstruction::hasFlags() const
{
    return RetComponent.mHasFlags;
}

// Print the instruction
void
ReturnInstruction::print(unknown::raw_ostream &OS, bool NewLine) const
{
    // address\tinst
    OS << "0x" << unknown::APInt(64, getInstructionAddress()).toString(16, false);
    OS << "\t";
    OS << getOpcodeName();
    if (NewLine)
    {
        OS << "\n";
    }
}

////////////////////////////////////////////////////////////
// Static
ReturnInstruction *
ReturnInstruction::get()
{
    return new ReturnInstruction();
}

////////////////////////////////////////////////////////////
//     ReturnImmInstruction
//
ReturnImmInstruction::ReturnImmInstruction(ConstantInt *ImmConstantInt) : TerminatorInstruction(OpCodeID::RetIMM)
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

// Is this instruction with flags?
bool
ReturnImmInstruction::hasFlags() const
{
    return RetIMMComponent.mHasFlags;
}

// Print the instruction
void
ReturnImmInstruction::print(unknown::raw_ostream &OS, bool NewLine) const
{
    // address\tinst
    OS << "0x" << unknown::APInt(64, getInstructionAddress()).toString(16, false);
    OS << "\t";
    OS << getOpcodeName();
    OS << " ";
    OS << getImmConstantInt()->getReadableName();
    if (NewLine)
    {
        OS << "\n";
    }
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
ReturnImmInstruction::get(ConstantInt *ImmConstantInt)
{
    return new ReturnImmInstruction(ImmConstantInt);
}

} // namespace uir
