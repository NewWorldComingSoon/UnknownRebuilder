#pragma once
#include <UnknownIR/InstructionBase.h>
#include <UnknownIR/Constant.h>

namespace uir {

class ReturnInst : public Instruction
{
public:
    ReturnInst();
    virtual ~ReturnInst();

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
    // Static
    static ReturnInst *get();
};

class ReturnImmInst : public Instruction
{
public:
    explicit ReturnImmInst(ConstantInt *ImmConstantInt);
    virtual ~ReturnImmInst();

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
    // Get the immediate constant int
    const ConstantInt *getImmConstantInt() const;

    // Set the immediate constant int
    void setImmConstantInt(ConstantInt *ImmConstantInt);

public:
    // Static
    static ReturnImmInst *get(ConstantInt *ImmConstantInt);
};

} // namespace uir
