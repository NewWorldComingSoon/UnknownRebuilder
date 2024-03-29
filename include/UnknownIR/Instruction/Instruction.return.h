#pragma once
#include <UnknownIR/InstructionBase.h>
#include <UnknownIR/Constant.h>

namespace uir {

class ReturnInstruction : public TerminatorInstruction
{
public:
    ReturnInstruction(Context &C);
    virtual ~ReturnInstruction();

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
    // Static
    static ReturnInstruction *get(Context &C);
};

class ReturnImmInstruction : public TerminatorInstruction
{
public:
    explicit ReturnImmInstruction(Context &C, ConstantInt *ImmConstantInt);
    virtual ~ReturnImmInstruction();

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
    // Get the immediate constant int
    const ConstantInt *getImmConstantInt() const;

    // Set the immediate constant int
    void setImmConstantInt(ConstantInt *ImmConstantInt);

public:
    // Static
    static ReturnImmInstruction *get(Context &C, ConstantInt *ImmConstantInt);
};

} // namespace uir
