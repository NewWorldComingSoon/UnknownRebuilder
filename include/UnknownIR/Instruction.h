#pragma once
#include <UnknownIR/OpCode.h>
#include <UnknownIR/User.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class Instruction : public User
{
private:
    uint64_t mInstructionAddress;

public:
    Instruction();
    virtual ~Instruction();

public:
    // Get/Set
    // Get the address of this instruction
    uint64_t getInstructionAddress() const;

    // Set the address of this instruction
    void setInstructionAddress(uint64_t InstructionAddress);

public:
    // Print
    // Print the instruction
    void print(unknown::raw_ostream &OS) const;
};

} // namespace uir
