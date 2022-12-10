#include "ContextImpl.h"
#include <Context.h>
#include <Type.h>

namespace uir {

ContextImpl::ContextImpl(Context &C) :
    mVoidTy(C, "void", Type::VoidTyID, 0),
    mFloatTy(C, "float", Type::FloatTyID, 32),
    mDoubleTy(C, "double", Type::DoubleTyID, 64),
    mLabelTy(C, "label", Type::LabelTyID, C.getModeBits()),
    mFunctionTy(C, "function", Type::FunctionTyID, 0)
{
}
ContextImpl ::~ContextImpl() {}

} // namespace uir
