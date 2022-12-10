#pragma once
#include <stdint.h>
#include <string>

#include <Type.h>

namespace uir {

class Context;

class ContextImpl
{
public:
    // Basic type instances
    Type mVoidTy;
    Type mFloatTy;
    Type mDoubleTy;
    Type mLabelTy;
    Type mFunctionTy;

public:
    explicit ContextImpl(Context &C);
    ~ContextImpl();
};

} // namespace uir