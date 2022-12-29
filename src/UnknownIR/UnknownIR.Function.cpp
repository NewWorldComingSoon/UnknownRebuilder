#include <Function.h>
#include <BasicBlock.h>
#include <Argument.h>
#include <FunctionContext.h>
#include <Module.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     Function
//
Function::Function(
    Context &C,
    const unknown::StringRef &FunctionName,
    Module *Parent,
    uint64_t FunctionAddressBegin,
    uint64_t FunctionAddressEnd) :
    Constant(Type::getFunctionTy(C), FunctionName),
    mFunctionName(FunctionName),
    mParent(Parent),
    mFunctionAddressBegin(FunctionAddressBegin),
    mFunctionAddressEnd(FunctionAddressEnd)
{
    // Clear ordered block name index.
    C.mImpl->mOrderedBlockNameIndex = 0;

    // Clear ordered local variable name index.
    C.mImpl->mOrderedLocalVarNameIndex = 0;
}

Function::~Function()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Get/Set
// Get parent module
const Module *
Function::getParent() const
{
    return mParent;
}
Module *
Function::getParent()
{
    return mParent;
}

// Set parent module
void
Function::setParent(Module *Parent)
{
    mParent = Parent;
}

// Get the begin/end address of this function
uint64_t
Function::getFunctionBeginAddress() const
{
    return mFunctionAddressBegin;
}

// Get the begin/end address of this function
uint64_t
Function::getFunctionEndAddress() const
{
    return mFunctionAddressEnd;
}

// Set the begin address of this function
void
Function::setFunctionBeginAddress(uint64_t FunctionBeginAddress)
{
    mFunctionAddressBegin = FunctionBeginAddress;
}

// Set the end address of this function
void
Function::setFunctionEndAddress(uint64_t FunctionEndAddress)
{
    mFunctionAddressEnd = FunctionEndAddress;
}

// Get the entry block of this function
const BasicBlock &
Function::getEntryBlock() const
{
    return front();
}

// Get the entry block of this function
BasicBlock &
Function::getEntryBlock()
{
    return front();
}

// Get the name of this function
const std::string
Function::getFunctionName() const
{
    return mFunctionName;
}

// Set the name of this function
void
Function::setFunctionName(const unknown::StringRef &FunctionName)
{
    mFunctionName = FunctionName;
}

// Get the attributes of this function
const Function::FunctionAttributesListType &
Function::getFunctionAttributes() const
{
    return mFunctionAttributesList;
}

// Set the attributes of this function
void
Function::setFunctionAttributes(const Function::FunctionAttributesListType &FunctionAttributes)
{
    mFunctionAttributesList = FunctionAttributes;
}

////////////////////////////////////////////////////////////
// Add
// Add function attribute to this function.
void
Function::addFnAttr(const unknown::StringRef &FunctionAttribute)
{
    auto Iter = std::find(mFunctionAttributesList.begin(), mFunctionAttributesList.end(), FunctionAttribute);
    if (Iter == mFunctionAttributesList.end())
    {
        mFunctionAttributesList.push_back(FunctionAttribute);
    }
}

// Remove function attribute from this function.
void
Function::removeFnAttr(const unknown::StringRef &FunctionAttribute)
{
    auto Iter = std::find(mFunctionAttributesList.begin(), mFunctionAttributesList.end(), FunctionAttribute);
    if (Iter != mFunctionAttributesList.end())
    {
        mFunctionAttributesList.erase(Iter);
    }
}

// Check if this function has a specific attribute
bool
Function::hasFnAttr(const unknown::StringRef &FunctionAttribute) const
{
    auto Iter = std::find(mFunctionAttributesList.begin(), mFunctionAttributesList.end(), FunctionAttribute);
    if (Iter != mFunctionAttributesList.end())
    {
        return true;
    }

    return false;
}

////////////////////////////////////////////////////////////
// Remove/Erase/Insert/Clear
// Remove the function from the its parent, but does not delete it.
void
Function::removeFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getFunctionList().empty())
    {
        return;
    }

    mParent->getFunctionList().remove(this);
}

// Remove the function from the its parent and delete it.
void
Function::eraseFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getFunctionList().empty())
    {
        return;
    }

    for (auto It = mParent->getFunctionList().begin(); It != mParent->getFunctionList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getFunctionList().erase(It);
            this->setParent(nullptr);
            --It;
        }
    }
}

// Insert a new basic block to this function
void
Function::insertBasicBlock(BasicBlock *BB)
{
    push_back(BB);
    BB->setParent(this);
}

////////////////////////////////////////////////////////////
// Static
// Generate a new function name by order
std::string
Function::generateOrderedFunctionName(Context &C)
{
    auto CurIdx = C.mImpl->mOrderedFunctionNameIndex++;
    return std::to_string(CurIdx);
}

////////////////////////////////////////////////////////////
// Virtual functions
// Get the readable name of this object
std::string
Function::getReadableName() const
{
    // function.func1
    std::string ReadableName = UIR_FUNCTION_VARIABLE_NAME_PREFIX;
    ReadableName += mFunctionName;

    return ReadableName;
}

// Print the function
void
Function::print(unknown::raw_ostream &OS, bool NewLine) const
{
    // TODO
}

} // namespace uir
