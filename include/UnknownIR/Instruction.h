#pragma once
#include <UnknownIR/OpCode.h>
#include <UnknownIR/User.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class Instruction : public User
{
public:
    Instruction();
    virtual ~Instruction();

public:
    // Print
    // Print the instruction
    void print(unknown::raw_ostream &OS) const;
};

} // namespace uir
