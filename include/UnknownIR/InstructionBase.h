#pragma once
#include <UnknownIR/OpCode.h>
#include <UnknownIR/User.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class BasicBlock;

class Instruction : public User
{
protected:
    OpCodeID mOpCodeID;
    uint64_t mInstructionAddress;
    BasicBlock *mParent;

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

public:
    // Print
    // Print the instruction
    void print(unknown::raw_ostream &OS) const;
};

} // namespace uir
