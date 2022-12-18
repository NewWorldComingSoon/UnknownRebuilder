#include <LocalVariable.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     LocalVariable
//
LocalVariable::LocalVariable(Type *Ty, const char *LocalVariableName) : Constant(Ty, LocalVariableName)
{
    //
    //
}

LocalVariable::~LocalVariable()
{
    //
    //
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

} // namespace uir
