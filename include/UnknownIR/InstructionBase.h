#pragma once
#include <UnknownIR/OpCode.h>
#include <UnknownIR/User.h>
#include <UnknownIR/FlagsVariable.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class BasicBlock;

class Instruction : public User
{
protected:
    OpCodeID mOpCodeID;
    uint64_t mInstructionAddress;
    BasicBlock *mParent;
    FlagsVariable *mFlagsVariable;

public:
    Instruction();
    Instruction(OpCodeID OpCodeId);
    virtual ~Instruction();

public:
    // Get/Set
    // Get the address of this instruction
    uint64_t getInstructionAddress() const;

    // Set the address of this instruction
    void setInstructionAddress(uint64_t InstructionAddress);

    // Get the parent of this instruction
    const BasicBlock *getParent() const;

    // Set the parent of this instruction
    void setParent(BasicBlock *BB);

    // Get the opcode of this instruction
    const OpCodeID getOpCodeID() const;

    // Set the opcode of this instruction
    void setOpCodeID(OpCodeID OpCodeId);

    // Get the flags variable of this instruction
    const FlagsVariable *getFlagsVariable() const;

    // Set the flags variable of this instruction
    void setFlagsVariable(FlagsVariable *FV);

public:
    // Print
    // Print the instruction
    void print(unknown::raw_ostream &OS) const;

public:
    // Static
    static Instruction *get(OpCodeID OpCodeId);
};

} // namespace uir
