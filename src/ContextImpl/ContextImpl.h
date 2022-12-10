#pragma once
#include <stdint.h>
#include <string>
#include <unordered_map>

#include <Type.h>

namespace uir {

class Context;

class ContextImpl
{
private:
    Context &mContext;

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

    // PointerType map
    std::unordered_map<Type *, PointerType *> mPointerTypes;

public:
    explicit ContextImpl(Context &C);
    ~ContextImpl();

public:
    PointerType *getPointerType(Type *ElmtTy);
};

} // namespace uir