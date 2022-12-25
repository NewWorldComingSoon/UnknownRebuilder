#pragma once
#include <UnknownIR/InstructionBase.h>
#include <UnknownIR/Constant.h>

namespace uir {

class BasicBlock;

class JmpAddrInstruction : public TerminatorInstruction
{
public:
    explicit JmpAddrInstruction(ConstantInt *JmpDest);
    virtual ~JmpAddrInstruction();

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
    // Get the JmpDest constant int
    const ConstantInt *getJmpDestConstantInt() const;

    // Set the JmpDest constant int
    void setJmpDestConstantInt(ConstantInt *JmpDestConstantInt);

public:
    // Static
    static JmpAddrInstruction *get(ConstantInt *JmpDest);
};

class JmpBBInstruction : public TerminatorInstruction
{
public:
    JmpBBInstruction();
    virtual ~JmpBBInstruction();
};

} // namespace uir
