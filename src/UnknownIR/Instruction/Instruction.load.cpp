#include <Instruction.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

LoadInstruction::LoadInstruction(Value *Ptr) :
    Instruction(
        OpCodeID::Load,
        dynamic_cast<PointerType *>(Ptr->getType()) ? dynamic_cast<PointerType *>(Ptr->getType())->getElementType()
                                                    : nullptr)
{
    assert(Ptr->getType()->isPointerTy() && "Ptr must be a pointer type!");

    // Insert pointer   -> op1
    insertOperandAndUpdateUsers(Ptr);
}

LoadInstruction::~LoadInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
LoadInstruction::getOpcodeName() const
{
    return LoadComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
LoadInstruction::getDefaultNumberOfOperands() const
{
    return LoadComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
LoadInstruction::hasResult() const
{
    return LoadComponent.mHasResult;
}

// Is this instruction with flags?
bool
LoadInstruction::hasFlags() const
{
    return LoadComponent.mHasFlags;
}

// Print the instruction
void
LoadInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << this->getReadableName();
    OS << UIR_OP_RESULT_SEPARATOR;
    OS << getOpcodeName();
    OS << UIR_OPCODE_SEPARATOR;
    OS << getPointerOperand()->getReadableName();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the pointer operand of this instruction
Value *
LoadInstruction::getPointerOperand()
{
    return getOperand(0);
}

// Get the pointer operand of this instruction
const Value *
LoadInstruction::getPointerOperand() const
{
    return getOperand(0);
}

// Set the pointer operand of this instruction
void
LoadInstruction::setPointerOperand(Value *Ptr)
{
    setOperandAndUpdateUsers(0, Ptr);
}

} // namespace uir