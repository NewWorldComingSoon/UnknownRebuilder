#pragma once
#include <UnknownIR/InstructionBase.h>

namespace uir {

class StoreInst : public Instruction
{
private:
    bool mIsVolatile;

public:
    explicit StoreInst(Value *Val, Value *Ptr, bool IsVolatile = false);
    virtual ~StoreInst();

public:
    // Virtual
    // Get the opcode name of this instruction
    virtual unknown::StringRef getOpcodeName() const override;

    // Get the default number of operands
    virtual uint32_t getDefaultNumberOfOperands() const override;

    // Is this instruction with flags?
    virtual bool hasFlags() const override;

    // Print the instruction
    virtual void print(unknown::raw_ostream &OS) const override;

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

public:
    // Static
    static StoreInst *get(Value *Val, Value *Ptr, bool IsVolatile = false);
};

} // namespace uir
