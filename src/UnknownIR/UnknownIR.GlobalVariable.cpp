#include <GlobalVariable.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     GlobalVariable
//
GlobalVariable::GlobalVariable(Type *Ty) : GlobalVariable(Ty, generateOrderedGlobalVarName(Ty->getContext()), 0)
{
    //
    //
}

GlobalVariable::GlobalVariable(Type *Ty, const unknown::StringRef &GlobalVariableName, uint64_t GlobalVariableAddress) :
    Constant(Ty, GlobalVariableName), mGlobalVariableAddress(GlobalVariableAddress)
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
// Get the address of this global variable
uint64_t
GlobalVariable::getGlobalVariableAddress() const
{
    return mGlobalVariableAddress;
}

// Set the address of this global variable
void
GlobalVariable::setGlobalVariableAddress(uint64_t GlobalVariableAddress)
{
    mGlobalVariableAddress = GlobalVariableAddress;
}

////////////////////////////////////////////////////////////
// Virtual functions
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

// Allocate a GlobalVariable
GlobalVariable *
GlobalVariable::get(Type *Ty, const unknown::StringRef &GlobalVariableName, uint64_t GlobalVariableAddress)
{
    return new GlobalVariable(Ty, GlobalVariableName, GlobalVariableAddress);
}

GlobalVariable *
GlobalVariable::get(Type *Ty)
{
    return new GlobalVariable(Ty);
}

} // namespace uir
