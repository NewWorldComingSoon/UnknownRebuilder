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

    // IntegerType instances
    IntegerType mInt1Ty;
    IntegerType mInt8Ty;
    IntegerType mInt16Ty;
    IntegerType mInt32Ty;
    IntegerType mInt64Ty;
    IntegerType mInt128Ty;

public:
    explicit ContextImpl(Context &C);
    ~ContextImpl();
};

} // namespace uir