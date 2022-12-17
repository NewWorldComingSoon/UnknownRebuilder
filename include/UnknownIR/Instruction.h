#pragma once
#include <UnknownIR/OpCode.h>
#include <UnknownIR/User.h>

namespace uir {

class Instruction : public User
{
public:
    Instruction();
    virtual ~Instruction();

private:
};

} // namespace uir
