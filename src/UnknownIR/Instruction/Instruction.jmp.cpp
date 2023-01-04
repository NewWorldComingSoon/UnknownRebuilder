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

// Is this instruction with result?
bool
JmpAddrInstruction::hasResult() const
{
    return JmpAddrComponent.mHasResult;
}

// Is this instruction with flags?
bool
JmpAddrInstruction::hasFlags() const
{
    return JmpAddrComponent.mHasFlags;
}

// Print the instruction
void
JmpAddrInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
    OS << " ";
    OS << getJmpDestConstantInt()->getName();
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

////////////////////////////////////////////////////////////
//     JmpBBInstruction
//
JmpBBInstruction::JmpBBInstruction(BasicBlock *DestBB) : TerminatorInstruction(OpCodeID::JmpBB)
{
    insertSuccessor(DestBB);
}

JmpBBInstruction::~JmpBBInstruction()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
JmpBBInstruction::getOpcodeName() const
{
    return JmpBBComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
JmpBBInstruction::getDefaultNumberOfOperands() const
{
    return JmpBBComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
JmpBBInstruction::hasResult() const
{
    return JmpBBComponent.mHasResult;
}

// Is this instruction with flags?
bool
JmpBBInstruction::hasFlags() const
{
    return JmpBBComponent.mHasFlags;
}

// Print the instruction
void
JmpBBInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
    OS << " ";
    OS << getDestinationBlock()->getReadableName();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the destination basic block
const BasicBlock *
JmpBBInstruction::getDestinationBlock() const
{
    return *successor_begin();
}

// Set the destination basic block
void
JmpBBInstruction::setDestinationBlock(BasicBlock *DestBB)
{
    setSuccessor(0, DestBB);
}

// Set the destination basic block and update its predecessor.
void
JmpBBInstruction::setDestinationBlockAndUpdatePredecessor(BasicBlock *DestBB)
{
    setSuccessorAndUpdatePredecessor(0, DestBB);
}

////////////////////////////////////////////////////////////
// Static
JmpBBInstruction *
JmpBBInstruction::get(BasicBlock *DestBB)
{
    return new JmpBBInstruction(DestBB);
}

} // namespace uir