#include <GlobalVariable.h>
#include <Module.h>

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

GlobalVariable::GlobalVariable(
    Type *Ty,
    const unknown::StringRef &GlobalVariableName,
    uint64_t GlobalVariableAddress,
    Module *Parent) :
    Constant(Ty, GlobalVariableName), mGlobalVariableAddress(GlobalVariableAddress), mParent(Parent)
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

// Get parent module
const Module *
GlobalVariable::getParent() const
{
    return mParent;
}

// Set parent module
void
GlobalVariable::setParent(Module *Parent)
{
    mParent = Parent;
}

// Remove/Erase
// Remove this global variable from its parent module
void
GlobalVariable::removeFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getGlobalVariableList().empty())
    {
        return;
    }

    mParent->getGlobalVariableList().remove(this);
}

// Erase this global variable from its parent module
void
GlobalVariable::eraseFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getGlobalVariableList().empty())
    {
        return;
    }

    for (auto It = mParent->getGlobalVariableList().begin(); It != mParent->getGlobalVariableList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getGlobalVariableList().erase(It);
            this->setParent(nullptr);
            --It;
        }
    }
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
