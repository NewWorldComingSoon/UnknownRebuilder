#pragma once
#include "User.h"

namespace uir {

class Constant : public User
{
public:
    Constant();
    virtual ~Constant();

private:
};

class ConstantInt : public Constant
{
public:
    ConstantInt();
    virtual ~ConstantInt();

private:
};

} // namespace uir
