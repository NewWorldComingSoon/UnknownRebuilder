#include "ContextImpl.h"
#include <Config.h>
#include <Context.h>
#include <Type.h>

#include <InternalErrors/InternalErrors.h>

namespace uir {

ContextImpl::ContextImpl(Context &C) :
    mContext(C),
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
    for (auto &PtrTy : mPointerTypes)
    {
        auto TempPtr = PtrTy.second;
        PtrTy.second = nullptr;
        delete TempPtr;
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
        // No ptri1 and ptri128
        uir_unreachable("ElmtTy->getTypeBits() == 1 || ElmtTy->getTypeBits() == 128");
        return nullptr;
    }

    // ptri8/ptri16/ptri32/ptri64
    std::string PtrTyName = UIR_PTR_TYPE_NAME_PREFIX + ElmtTy->getTypeName();
    PointerType *PtrTy = new PointerType(mContext, ElmtTy, PtrTyName);
    mPointerTypes[ElmtTy] = PtrTy;
    return PtrTy;
}

} // namespace uir
