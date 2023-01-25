#include <Instruction.h>

#include <unknown/ADT/StringExtras.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {
////////////////////////////////////////////////////////////
// Ctor/Dtor
StoreInstruction::StoreInstruction(Context &C, Value *Val, Value *Ptr, bool IsVolatile) :
    Instruction(C, OpCodeID::Store), mIsVolatile(IsVolatile)
{
    assert(Ptr->getType()->isPointerTy() && "Ptr is not a pointer type!");

    // Insert value   -> op1
    insertOperandAndUpdateUsers(Val);

    // Insert pointer -> op2
    insertOperandAndUpdateUsers(Ptr);
}

StoreInstruction::~StoreInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
StoreInstruction::getOpcodeName() const
{
    return StoreComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
StoreInstruction::getDefaultNumberOfOperands() const
{
    return StoreComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
StoreInstruction::hasResult() const
{
    return StoreComponent.mHasResult;
}

// Is this instruction with flags?
bool
StoreInstruction::hasFlags() const
{
    return StoreComponent.mHasFlags;
}

// Print the instruction
void
StoreInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
    OS << UIR_OPCODE_SEPARATOR;
    OS << getValueOperand()->getReadableName();
    OS << UIR_OP_SEPARATOR;
    OS << getPointerOperand()->getReadableName();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the value operand of this instruction
Value *
StoreInstruction::getValueOperand()
{
    return getOperand(0);
}

// Get the value operand of this instruction
const Value *
StoreInstruction::getValueOperand() const
{
    return getOperand(0);
}

// Set the value operand of this instruction
void
StoreInstruction::setValueOperand(Value *Val)
{
    setOperandAndUpdateUsers(0, Val);
}

// Get the pointer operand of this instruction
Value *
StoreInstruction::getPointerOperand()
{
    return getOperand(1);
}

// Get the pointer operand of this instruction
const Value *
StoreInstruction::getPointerOperand() const
{
    return getOperand(1);
}

// Set the pointer operand of this instruction
void
StoreInstruction::setPointerOperand(Value *Ptr)
{
    setOperandAndUpdateUsers(1, Ptr);
}

// Get the is volatile of this instruction
bool
StoreInstruction::isVolatile() const
{
    return mIsVolatile;
}

// Set the volatile of this instruction
void
StoreInstruction::setVolatile(bool IsVolatile)
{
    mIsVolatile = IsVolatile;
}

////////////////////////////////////////////////////////////
// Static
StoreInstruction *
StoreInstruction::get(Context &C, Value *Val, Value *Ptr, bool IsVolatile)
{
    return new StoreInstruction(C, Val, Ptr, IsVolatile);
}

} // namespace uir
