#include <LocalVariable.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     LocalVariable
//
LocalVariable::LocalVariable(Type *Ty) :
    LocalVariable(
        Ty,
        Ty == Type::getVoidTy(Ty->getContext()) ? "LocalVoid" : generateOrderedLocalVarName(Ty->getContext()),
        0)
{
    //
}

LocalVariable::LocalVariable(Type *Ty, const unknown::StringRef &LocalVariableName, uint64_t LocalVariableAddress) :
    Constant(Ty, LocalVariableName), mLocalVariableAddress(LocalVariableAddress)
{
    //
}

LocalVariable::~LocalVariable()
{
    //
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the address of this local variable
uint64_t
LocalVariable::getLocalVariableAddress() const
{
    return mLocalVariableAddress;
}

// Set the address of this local variable
void
LocalVariable::setLocalVariableAddress(uint64_t LocalVariableAddress)
{
    mLocalVariableAddress = LocalVariableAddress;
}

////////////////////////////////////////////////////////////
// Static
// Generate a new value name by order
std::string
LocalVariable::generateOrderedLocalVarName(Context &C)
{
    auto CurIdx = C.mImpl->mOrderedLocalVarNameIndex++;
    return std::to_string(CurIdx);
}

// Allocate a LocalVariable
LocalVariable *
LocalVariable::get(Type *Ty, const unknown::StringRef &LocalVariableName, uint64_t LocalVariableAddress)
{
    return new LocalVariable(Ty, LocalVariableName, LocalVariableAddress);
}

LocalVariable *
LocalVariable::get(Type *Ty)
{
    return new LocalVariable(Ty);
}

} // namespace uir
