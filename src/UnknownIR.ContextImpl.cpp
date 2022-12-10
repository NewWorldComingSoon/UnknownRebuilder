#include "ContextImpl.h"
#include <Config.h>
#include <Context.h>
#include <Type.h>

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
ContextImpl::getPointerType(Type *ElmtTy, uint32_t ElmtBits)
{
    PointerTypeKey PtrTyKey;
    PtrTyKey.ElmtTy = ElmtTy;
    PtrTyKey.ElmtBits = ElmtBits;

    auto It = mPointerTypes.find(PtrTyKey);
    if (It != mPointerTypes.end())
    {
        return It->second;
    }

    // ptri8/ptri16/ptri32/ptri64/ptri128
    std::string PtrTyName = UIR_PTR_TYPE_NAME_PREFIX + ElmtTy->getTypeName();
    PointerType *PtrTy = new PointerType(mContext, ElmtTy, PtrTyName, ElmtBits);
    mPointerTypes[PtrTyKey] = PtrTy;
    return PtrTy;
}

} // namespace uir
