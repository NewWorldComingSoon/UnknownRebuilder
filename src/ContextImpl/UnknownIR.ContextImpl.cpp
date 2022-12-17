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
        delete IntTy.second;
        IntTy.second = nullptr;
    }

    for (auto &PtrTy : mPointerTypes)
    {
        delete PtrTy.second;
        PtrTy.second = nullptr;
    }

    for (auto &CstIntTy : mIntConstants)
    {
        delete CstIntTy.second;
        CstIntTy.second = nullptr;
    }
}

PointerType *
ContextImpl::getPointerType(Type *ElmtTy)
{
    auto It = mPointerTypes.find(ElmtTy);
    if (It != mPointerTypes.end())
    {
        return It->second;
    }

    if (ElmtTy->getTypeBits() == 1 || ElmtTy->getTypeBits() == 128)
    {
        // Not support i1* and i128* currently
        uir_unreachable("ElmtTy->getTypeBits() == 1 || ElmtTy->getTypeBits() == 128");
        return nullptr;
    }

    // i8*/i16*/i32*/i64*
    std::string PtrTyName = ElmtTy->getTypeName() + UIR_PTR_TYPE_NAME_SUFFIX;
    PointerType *PtrTy = new PointerType(mContext, ElmtTy, PtrTyName);
    mPointerTypes[ElmtTy] = PtrTy;
    return PtrTy;
}

} // namespace uir
