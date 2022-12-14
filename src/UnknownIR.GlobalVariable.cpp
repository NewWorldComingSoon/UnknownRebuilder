#include <GlobalVariable.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     GlobalVariable
//
GlobalVariable::GlobalVariable(Type *Ty, const std::string GlobalVariableName) : Constant(Ty, GlobalVariableName)
{
    //
    //
}

GlobalVariable::~GlobalVariable()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the readable name of this object
std::string
GlobalVariable::getReadableName() const
{
    // %global i32
    std::string ReadableName = UIR_GLOBAL_VARIABLE_NAME_PREFIX;
    ReadableName += mValueName;
    ReadableName += " ";
    ReadableName += mType->getTypeName();

    return ReadableName;
}

////////////////////////////////////////////////////////////
// Static
// Generate a new value name by order
std::string
GlobalVariable::generateOrderedGlobalVarName(Context &C)
{
    auto CurIdx = C.mImpl->mOrderedGlobalVarNameIndex++;
    return std::to_string(CurIdx);
}

} // namespace uir
