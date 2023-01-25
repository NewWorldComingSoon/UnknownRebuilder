#pragma once
#include <UnknownIR/InstructionBase.h>

namespace uir {

class GetBitPtrInstruction : public Instruction
{
public:
    explicit GetBitPtrInstruction(PointerType *ResType, Value *Ptr, Value *BitIndex);
    virtual ~GetBitPtrInstruction();

public:
    // Virtual
    // Get the opcode name of this instruction
    virtual unknown::StringRef getOpcodeName() const override;

    // Get the default number of operands
    virtual uint32_t getDefaultNumberOfOperands() const override;

    // Is this instruction with result?
    virtual bool hasResult() const override;

    // Is this instruction with flags?
    virtual bool hasFlags() const override;

    // Print the instruction
    virtual void printInst(unknown::raw_ostream &OS) const override;

public:
    // Get/Set
    // Get the pointer operand of this instruction
    Value *getPointerOperand();

    // Get the pointer operand of this instruction
    const Value *getPointerOperand() const;

    // Set the pointer operand of this instruction
    void setPointerOperand(Value *Ptr);

    // Get the bit index operand of this instruction
    Value *getBitIndexOperand();

    // Get the bit index operand of this instruction
    const Value *getBitIndexOperand() const;

    // Set the bit index operand of this instruction
    void setBitIndexOperand(Value *BitIndex);

public:
    // Static
    static GetBitPtrInstruction *get(PointerType *ResType, Value *Ptr, Value *BitIndex);
};

} // namespace uir
