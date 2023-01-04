#include <Instruction.h>
#include <FlagsVariable.h>
#include <BasicBlock.h>

#include <unknown/ADT/StringExtras.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {
////////////////////////////////////////////////////////////
//     JccAddrInstruction
//
JccAddrInstruction::JccAddrInstruction(ConstantInt *JccDest, ConstantInt *JccNormal, FlagsVariable *FlagsVar) :
    TerminatorInstruction(OpCodeID::JccAddr)
{
    // Insert value   -> op1
    insertOperandAndUpdateUsers(JccDest);

    // Insert value   -> op2
    insertOperandAndUpdateUsers(JccNormal);

    // Set flags variable
    setFlagsVariableAndUpdateUsers(FlagsVar);
}

JccAddrInstruction::~JccAddrInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
JccAddrInstruction::getOpcodeName() const
{
    return JccAddrComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
JccAddrInstruction::getDefaultNumberOfOperands() const
{
    return JccAddrComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
JccAddrInstruction::hasResult() const
{
    return JccAddrComponent.mHasResult;
}

// Is this instruction with flags?
bool
JccAddrInstruction::hasFlags() const
{
    return JccAddrComponent.mHasFlags;
}

// Print the instruction
void
JccAddrInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
    OS << UIR_SEPARATOR;
    OS << getJccDestConstantInt()->getName();
    OS << UIR_SEPARATOR;
    OS << getJccNormalConstantInt()->getName();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the JccDest constant int
const ConstantInt *
JccAddrInstruction::getJccDestConstantInt() const
{
    return dynamic_cast<const ConstantInt *>(getOperand(0));
}

// Get the JccNormal constant int
const ConstantInt *
JccAddrInstruction::getJccNormalConstantInt() const
{
    return dynamic_cast<const ConstantInt *>(getOperand(1));
}

// Set the JccDest constant int
void
JccAddrInstruction::setJccDestConstantInt(ConstantInt *JccDestConstantInt)
{
    setOperandAndUpdateUsers(0, JccDestConstantInt);
}

// Set the JccNormal constant int
void
JccAddrInstruction::setJccNormalConstantInt(ConstantInt *JccNormalConstantInt)
{
    setOperandAndUpdateUsers(1, JccNormalConstantInt);
}

////////////////////////////////////////////////////////////
// Static
JccAddrInstruction *
JccAddrInstruction::get(ConstantInt *JccDest, ConstantInt *JccNormal, FlagsVariable *FlagsVar)
{
    return new JccAddrInstruction(JccDest, JccNormal, FlagsVar);
}

////////////////////////////////////////////////////////////
//     JccBBInstruction
//
JccBBInstruction::JccBBInstruction(BasicBlock *JccDestBB, BasicBlock *JccNormalBB, FlagsVariable *FlagsVar) :
    TerminatorInstruction(OpCodeID::JccBB)
{
    // Insert successor1
    insertSuccessor(JccDestBB);

    // Insert successor2
    insertSuccessor(JccNormalBB);

    // Set flags variable
    setFlagsVariableAndUpdateUsers(FlagsVar);
}

JccBBInstruction::~JccBBInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
JccBBInstruction::getOpcodeName() const
{
    return JccBBComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
JccBBInstruction::getDefaultNumberOfOperands() const
{
    return JccBBComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
JccBBInstruction::hasResult() const
{
    return JccBBComponent.mHasResult;
}

// Is this instruction with flags?
bool
JccBBInstruction::hasFlags() const
{
    return JccBBComponent.mHasFlags;
}

// Print the instruction
void
JccBBInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
    OS << UIR_SEPARATOR;
    OS << getDestinationBlock()->getReadableName();
    OS << UIR_SEPARATOR;
    OS << getNormalBlock()->getReadableName();
}

// Print the operand
void
JccBBInstruction::printOp(unknown::XMLPrinter &Printer) const
{
    Printer.OpenElement(getPropertyOpCode().str().c_str());
    Printer.PushAttribute(getPropertyName().str().c_str(), getOpcodeName().str().c_str());
    Printer.CloseElement();

    Printer.OpenElement(getPropertyOp().str().c_str());
    Printer.PushAttribute(getPropertyName().str().c_str(), getDestinationBlock()->getReadableName().c_str());
    Printer.CloseElement();

    Printer.OpenElement(getPropertyOp().str().c_str());
    Printer.PushAttribute(getPropertyName().str().c_str(), getNormalBlock()->getReadableName().c_str());
    Printer.CloseElement();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the destination basic block.
const BasicBlock *
JccBBInstruction::JccBBInstruction::getDestinationBlock() const
{
    return *successor_begin();
}

// Get the normal basic block.
const BasicBlock *
JccBBInstruction::getNormalBlock() const
{
    auto It = successor_begin();
    ++It;
    return *It;
}

// Set the destination basic block.
void
JccBBInstruction::setDestinationBlock(BasicBlock *DestBB)
{
    setSuccessor(0, DestBB);
}

// Set the destination basic block and update its predecessor.
void
JccBBInstruction::setDestinationBlockAndUpdatePredecessor(BasicBlock *DestBB)
{
    setSuccessorAndUpdatePredecessor(0, DestBB);
}

// Set the normal basic block.
void
JccBBInstruction::setNormalBlock(BasicBlock *NormalBB)
{
    setSuccessor(1, NormalBB);
}

// Set the normal basic block and update its predecessor.
void
JccBBInstruction::setNormalBlockAndUpdatePredecessor(BasicBlock *NormalBB)
{
    setSuccessorAndUpdatePredecessor(1, NormalBB);
}

////////////////////////////////////////////////////////////
// Static
JccBBInstruction *
JccBBInstruction::get(BasicBlock *JccDestBB, BasicBlock *JccNormalBB, FlagsVariable *FlagsVar)
{
    return new JccBBInstruction(JccDestBB, JccNormalBB, FlagsVar);
}

} // namespace uir
