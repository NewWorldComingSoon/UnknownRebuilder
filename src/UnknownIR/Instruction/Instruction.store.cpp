#pragma once
#include <Instruction.h>

namespace uir {
////////////////////////////////////////////////////////////
// Ctor/Dtor
StoreInst::StoreInst(Value *Val, Value *Ptr, bool IsVolatile) : Instruction(OpCodeID::Store), mIsVolatile(IsVolatile)
{
    // Insert value   -> op1
    insertOperandAndUpdateUsers(Val);

    // Insert pointer -> op2
    insertOperandAndUpdateUsers(Ptr);
}

StoreInst::~StoreInst()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
StoreInst::getOpcodeName() const
{
    return StoreComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
StoreInst::getDefaultNumberOfOperands() const
{
    return StoreComponent.mNumberOfOperands;
}

// Is this instruction with flags?
bool
StoreInst::hasFlags() const
{
    return StoreComponent.mHasFlags;
}

// Print the instruction
void
StoreInst::print(unknown::raw_ostream &OS) const
{
    // TODO
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the value operand of this instruction
Value *
StoreInst::getValueOperand()
{
    return getOperand(0);
}

const Value *
StoreInst::getValueOperand() const
{
    return getOperand(0);
}

// Set the value operand of this instruction
void
StoreInst::setValueOperand(Value *Val)
{
    setOperandAndUpdateUsers(0, Val);
}

// Get the pointer operand of this instruction
Value *
StoreInst::getPointerOperand()
{
    return getOperand(1);
}

const Value *
StoreInst::getPointerOperand() const
{
    return getOperand(1);
}

// Set the pointer operand of this instruction
void
StoreInst::setPointerOperand(Value *Ptr)
{
    setOperandAndUpdateUsers(1, Ptr);
}

// Get the is volatile of this instruction
bool
StoreInst::isVolatile() const
{
    return mIsVolatile;
}

// Set the volatile of this instruction
void
StoreInst::setVolatile(bool IsVolatile)
{
    mIsVolatile = IsVolatile;
}

////////////////////////////////////////////////////////////
// Static
StoreInst *
get(Value *Val, Value *Ptr, bool IsVolatile)
{
    return new StoreInst(Val, Ptr, IsVolatile);
}

} // namespace uir
