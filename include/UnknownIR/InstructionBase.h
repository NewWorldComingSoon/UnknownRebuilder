#pragma once
#include <UnknownIR/OpCode.h>
#include <UnknownIR/User.h>
#include <UnknownIR/FlagsVariable.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>
#include <UnknownUtils/unknown/ADT/StringRef.h>

namespace uir {

class BasicBlock;

class Instruction : public User
{
protected:
    OpCodeID mOpCodeID;
    uint64_t mInstructionAddress;
    BasicBlock *mParent;
    FlagsVariable *mFlagsVariable;
    LocalVariable *mStackVariable;

public:
    Instruction();
    explicit Instruction(OpCodeID OpCodeId);
    virtual ~Instruction();

public:
    // Virtual
    // Get the opcode name of this instruction
    virtual unknown::StringRef getOpcodeName() const;

    // Get the default number of operands
    virtual uint32_t getDefaultNumberOfOperands() const;

    // Is this instruction with flags?
    virtual bool hasFlags() const;

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

    // Set the flags variable of this instruction and update its users
    void setFlagsVariableAndUpdateUsers(FlagsVariable *FV);

    // Get the stack variable of this instruction
    const LocalVariable *getStackVariable() const;

    // Set the stack variable of this instruction
    void setStackVariable(LocalVariable *SV);

    // Set the stack variable of this instruction and update its users
    void setStackVariableAndUpdateUsers(LocalVariable *SV);

public:
    // Print
    // Print the instruction
    void print(unknown::raw_ostream &OS) const;

public:
    // Static
    static Instruction *get(OpCodeID OpCodeId);
};

} // namespace uir
