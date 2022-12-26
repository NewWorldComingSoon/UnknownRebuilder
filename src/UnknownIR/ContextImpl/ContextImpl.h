#pragma once
#include <cstdint>
#include <string>
#include <map>
#include <unordered_map>

#include <Type.h>

#include <UnknownUtils/unknown/ADT/APInt.h>

namespace uir {

class Context;
class ConstantInt;
class GlobalVariable;

class ContextImpl
{
private:
    Context &mContext;

public:
    // Ordered index
    uint64_t mOrderedLocalVarNameIndex;
    uint64_t mOrderedGlobalVarNameIndex;
    uint64_t mOrderedFunctionNameIndex;
    uint64_t mOrderedBlockNameIndex;

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
    std::map<unknown::APInt, ConstantInt *> mIntConstants;

    // GlobalVariables map
    std::unordered_map<uint64_t, GlobalVariable *> mGlobalVariables;

public:
    explicit ContextImpl(Context &C);
    ~ContextImpl();
};

} // namespace uir