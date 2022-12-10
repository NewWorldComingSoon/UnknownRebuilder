#include "ContextImpl.h"
#include <Context.h>
#include <Type.h>

namespace uir {

ContextImpl::ContextImpl(Context &C) :
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

ContextImpl ::~ContextImpl() {}

} // namespace uir
