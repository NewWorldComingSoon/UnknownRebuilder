#pragma once
#include <Instruction.h>

namespace uir {
////////////////////////////////////////////////////////////
// Ctor/Dtor
StoreInst::StoreInst(Value *Val, Value *Ptr, bool IsVolatile) :
    Instruction(OpCodeID::Store), mValueOperand(Val), mPointerOperand(Ptr), mIsVolatile(IsVolatile)
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
// Get/Set
// Get the value operand of this instruction
Value *
StoreInst::getValueOperand()
{
    return mValueOperand;
}

const Value *
StoreInst::getValueOperand() const
{
    return mValueOperand;
}

// Set the value operand of this instruction
void
StoreInst::setValueOperand(Value *Val)
{
    mValueOperand = Val;
}

// Get the pointer operand of this instruction
Value *
StoreInst::getPointerOperand()
{
    return mPointerOperand;
}

const Value *
StoreInst::getPointerOperand() const
{
    return mPointerOperand;
}

// Set the pointer operand of this instruction
void
StoreInst::setPointerOperand(Value *Ptr)
{
    mPointerOperand = Ptr;
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
