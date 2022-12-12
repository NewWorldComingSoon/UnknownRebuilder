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
private:
    uint64_t mVal;

public:
    ConstantInt();
    virtual ~ConstantInt();

public:
    // Get/Set the value of ConstantInt
    uint64_t getValue() const;
    void setValue(uint64_t Val);
};

} // namespace uir
