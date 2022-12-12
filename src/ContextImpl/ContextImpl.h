#pragma once
#include <stdint.h>
#include <string>
#include <unordered_map>

#include <Type.h>

namespace uir {

class Context;
class ConstantInt;

class ContextImpl
{
private:
    Context &mContext;

public:
    //Ordered index
    uint64_t mOrderedValueNameIndex;

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

    // IntegerTypes map
    std::unordered_map<uint32_t, IntegerType *> mIntegerTypes;

    // PointerType map
    std::unordered_map<Type *, PointerType *> mPointerTypes;

    // IntConstants map
    using ConstantIntMapTy = std::unordered_map<uint64_t, ConstantInt *>;
    ConstantIntMapTy mIntConstants;

public:
    explicit ContextImpl(Context &C);
    ~ContextImpl();

public:
    PointerType *getPointerType(Type *ElmtTy);
};

} // namespace uir