#pragma once
#include <UnknownIR/InstructionBase.h>

namespace uir {

class UnknownInstruction : public Instruction
{
private:
    std::string mUnknownStr;

public:
    explicit UnknownInstruction(Context &C, unknown::StringRef UnknownStr = "");
    virtual ~UnknownInstruction();

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
    // Get the unknown string
    std::string getUnknownStr() const;

public:
    // Static
    static UnknownInstruction *get(Context &C, unknown::StringRef UnknownStr = "");
};

} // namespace uir
