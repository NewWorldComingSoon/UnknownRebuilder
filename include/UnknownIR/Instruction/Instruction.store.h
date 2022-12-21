#pragma once
#include <UnknownIR/InstructionBase.h>

namespace uir {

class StoreInst : public Instruction
{
private:
    bool mIsVolatile;
    Value *mValueOperand;
    Value *mPointerOperand;

public:
    StoreInst(Value *Val, Value *Ptr, bool IsVolatile = false);
    virtual ~StoreInst();

public:
    // Get/Set
    // Get the value operand of this instruction
    Value *getValueOperand();
    const Value *getValueOperand() const;

    // Set the value operand of this instruction
    void setValueOperand(Value *Val);

    // Get the pointer operand of this instruction
    Value *getPointerOperand();
    const Value *getPointerOperand() const;

    // Set the pointer operand of this instruction
    void setPointerOperand(Value *Ptr);

    // Get the is volatile of this instruction
    bool isVolatile() const;

    // Set the volatile of this instruction
    void setVolatile(bool IsVolatile);
};

} // namespace uir
