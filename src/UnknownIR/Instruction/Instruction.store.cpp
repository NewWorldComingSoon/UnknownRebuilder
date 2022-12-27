#include <Instruction.h>

#include <unknown/ADT/StringExtras.h>

namespace uir {
////////////////////////////////////////////////////////////
// Ctor/Dtor
StoreInstruction::StoreInstruction(Value *Val, Value *Ptr, bool IsVolatile) :
    Instruction(OpCodeID::Store), mIsVolatile(IsVolatile)
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

// Is this instruction with flags?
bool
StoreInstruction::hasFlags() const
{
    return StoreComponent.mHasFlags;
}

// Print the instruction
void
StoreInstruction::print(unknown::raw_ostream &OS) const
{
    // address\tinst
    OS << "0x" << unknown::APInt(64, getInstructionAddress()).toString(16, false);
    OS << "\t";
    OS << getOpcodeName();
    OS << " ";
    OS << getValueOperand()->getReadableName();
    OS << ", ";
    OS << getPointerOperand()->getReadableName();
    OS << "\n";
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
StoreInstruction::get(Value *Val, Value *Ptr, bool IsVolatile)
{
    return new StoreInstruction(Val, Ptr, IsVolatile);
}

} // namespace uir
