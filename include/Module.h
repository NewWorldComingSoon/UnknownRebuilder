#pragma once
#include "Function.h"

namespace uir {

class Module
{
protected:
    Context &mContext;

public:
    explicit Module(Context &C);
    virtual ~Module();

public:
    // Context
    Context &getContext() const;
};

} // namespace uir
