#include <Instruction.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

GetBitPtrInstruction::GetBitPtrInstruction(PointerType *ResType, Value *Ptr, Value *BitIndex) :
    Instruction(OpCodeID::GetBitPtr, ResType)
{
    assert(ResType->isPointerTy() && "ResType must be a pointer type!");
    assert(Ptr->getType()->isPointerTy() && "Ptr must be a pointer type!");

    // Insert pointer   -> op1
    insertOperandAndUpdateUsers(Ptr);

    // Insert Bit Index -> op2
    insertOperandAndUpdateUsers(BitIndex);
}

GetBitPtrInstruction::~GetBitPtrInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
GetBitPtrInstruction::getOpcodeName() const
{
    return GBPComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
GetBitPtrInstruction::getDefaultNumberOfOperands() const
{
    return GBPComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
GetBitPtrInstruction::hasResult() const
{
    return GBPComponent.mHasResult;
}

// Is this instruction with flags?
bool
GetBitPtrInstruction::hasFlags() const
{
    return GBPComponent.mHasFlags;
}

// Print the instruction
void
GetBitPtrInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << this->getReadableName();
    OS << UIR_OP_RESULT_SEPARATOR;
    OS << getOpcodeName();
    OS << UIR_OPCODE_SEPARATOR;
    OS << getPointerOperand()->getReadableName();
    OS << UIR_OP_SEPARATOR;
    OS << getBitIndexOperand()->getReadableName();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the pointer operand of this instruction
Value *
GetBitPtrInstruction::getPointerOperand()
{
    return getOperand(0);
}

// Get the pointer operand of this instruction
const Value *
GetBitPtrInstruction::getPointerOperand() const
{
    return getOperand(0);
}

// Set the pointer operand of this instruction
void
GetBitPtrInstruction::setPointerOperand(Value *Ptr)
{
    setOperandAndUpdateUsers(0, Ptr);
}

// Get the bit index operand of this instruction
Value *
GetBitPtrInstruction::getBitIndexOperand()
{
    return getOperand(1);
}

// Get the bit index operand of this instruction
const Value *
GetBitPtrInstruction::getBitIndexOperand() const
{
    return getOperand(1);
}

// Set the bit index operand of this instruction
void
GetBitPtrInstruction::setBitIndexOperand(Value *BitIndex)
{
    setOperandAndUpdateUsers(1, BitIndex);
}

////////////////////////////////////////////////////////////
// Static
GetBitPtrInstruction *
GetBitPtrInstruction::get(PointerType *ResType, Value *Ptr, Value *BitIndex)
{
    return new GetBitPtrInstruction(ResType, Ptr, BitIndex);
}

} // namespace uir
