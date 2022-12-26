#include "ContextImpl.h"
#include <Context.h>
#include <Type.h>

#include <Internal/InternalConfig/InternalConfig.h>
#include <Internal/InternalErrors/InternalErrors.h>

namespace uir {

ContextImpl::ContextImpl(Context &C) :
    mContext(C),
    mOrderedLocalVarNameIndex(0),
    mOrderedGlobalVarNameIndex(0),
    mOrderedFunctionNameIndex(0),
    mOrderedBlockNameIndex(0),
    mVoidTy(C, "void", Type::VoidTyID, 0),
    mFloatTy(C, "float", Type::FloatTyID, 32),
    mDoubleTy(C, "double", Type::DoubleTyID, 64),
    mLabelTy(C, "label", Type::LabelTyID, C.getModeBits()),
    mFunctionTy(C, "function", Type::FunctionTyID, 0),
    mInt1Ty(C, "i1", 1),
    mInt8Ty(C, "i8", 8),
    mInt16Ty(C, "i16", 16),
    mInt32Ty(C, "i32", 32),
    mInt64Ty(C, "i64", 64),
    mInt128Ty(C, "i128", 128)
{
}

ContextImpl ::~ContextImpl()
{
    mOrderedLocalVarNameIndex = 0;
    mOrderedGlobalVarNameIndex = 0;
    mOrderedFunctionNameIndex = 0;
    mOrderedBlockNameIndex = 0;

    for (auto &IntTy : mIntegerTypes)
    {
        if (IntTy.second)
        {
            delete IntTy.second;
        }

        IntTy.second = nullptr;
    }

    for (auto &PtrTy : mPointerTypes)
    {
        if (PtrTy.second)
        {
            delete PtrTy.second;
        }

        PtrTy.second = nullptr;
    }

    for (auto &CI : mIntConstants)
    {
        if (CI.second)
        {
            delete CI.second;
        }

        CI.second = nullptr;
    }

    for (auto &GV : mGlobalVariables)
    {
        if (GV.second)
        {
            delete GV.second;
        }

        GV.second = nullptr;
    }
}

} // namespace uir
