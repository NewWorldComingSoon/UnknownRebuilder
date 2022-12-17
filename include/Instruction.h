#pragma once
#include "OpCode.h"
#include "User.h"

namespace uir {

class Instruction : public User
{
public:
    Instruction();
    virtual ~Instruction();

private:
};

} // namespace uir
