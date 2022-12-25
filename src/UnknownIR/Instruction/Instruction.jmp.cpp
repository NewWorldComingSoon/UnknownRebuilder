#include <Instruction.h>
#include <BasicBlock.h>

#include <unknown/ADT/StringExtras.h>

namespace uir {
////////////////////////////////////////////////////////////
//     JmpAddrInstruction
//
JmpAddrInstruction::JmpAddrInstruction(ConstantInt *JmpDest) : TerminatorInstruction(OpCodeID::JmpAddr)
{
    // Insert value   -> op1
    insertOperandAndUpdateUsers(JmpDest);
}

JmpAddrInstruction::~JmpAddrInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
JmpAddrInstruction::getOpcodeName() const
{
    return JmpAddrComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
JmpAddrInstruction::getDefaultNumberOfOperands() const
{
    return JmpAddrComponent.mNumberOfOperands;
}

// Is this instruction with flags?
bool
JmpAddrInstruction::hasFlags() const
{
    return JmpAddrComponent.mHasFlags;
}

// Print the instruction
void
JmpAddrInstruction::print(unknown::raw_ostream &OS) const
{
    // address\tinst
    OS << "0x" << unknown::utohexstr(getInstructionAddress());
    OS << "\t";
    OS << getOpcodeName();
    OS << " ";
    OS << getJmpDestConstantInt()->getReadableName();
    OS << "\n";
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the JmpDest constant int
const ConstantInt *
JmpAddrInstruction::getJmpDestConstantInt() const
{
    return dynamic_cast<const ConstantInt *>(getOperand(0));
}

// Set the JmpDest constant int
void
JmpAddrInstruction::setJmpDestConstantInt(ConstantInt *JmpDestConstantInt)
{
    setOperandAndUpdateUsers(0, JmpDestConstantInt);
}

////////////////////////////////////////////////////////////
// Static
JmpAddrInstruction *
JmpAddrInstruction::get(ConstantInt *JmpDest)
{
    return new JmpAddrInstruction(JmpDest);
}

} // namespace uir