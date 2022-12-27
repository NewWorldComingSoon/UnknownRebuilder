#include <Module.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     Module
//

////////////////////////////////////////////////////////////
// Ctor/Dtor
Module::Module(Context &C, unknown::StringRef ModuleName) : mContext(C), mModuleName(ModuleName)
{
    // Clear all the name index
    C.mImpl->clearOrderedNameIndex();
}

Module::~Module()
{
    //
    //
}

////////////////////////////////////////////////////////////
// FunctionList
// Get function list
const Module::FunctionSetType &
Module::getFunctionList() const
{
    return mFunctionList;
}

Module::FunctionSetType &
Module::getFunctionList()
{
    return mFunctionList;
}

// Get global variable list
const Module::GlobalVariableSetType &
Module::getGlobalVariableList() const
{
    return mGlobalVariableList;
}

Module::GlobalVariableSetType &
Module::getGlobalVariableList()
{
    return mGlobalVariableList;
}

////////////////////////////////////////////////////////////
// Context
// Get context
Context &
Module::getContext() const
{
    return mContext;
}

////////////////////////////////////////////////////////////
// Get/Set
// Get/Set the name of module
std::string
Module::getModuleName() const
{
    return mModuleName;
}

void
Module::setModuleName(unknown::StringRef ModuleName)
{
    mModuleName = ModuleName;
}

// Get the specified function in the module
std::optional<Function *>
Module::getFunction(unknown::StringRef FunctionName) const
{
    for (Function *Func : mFunctionList)
    {
        if (Func->getName().compare(FunctionName) == 0)
        {
            return Func;
        }
    }

    return {};
}

// Get the specified function by address in the module
std::optional<Function *>
Module::getFunction(uint64_t Address) const
{
    for (Function *Func : mFunctionList)
    {
        if (Func->getFunctionBeginAddress() == Address)
        {
            return Func;
        }
    }

    return {};
}

// Get the specified global variable by name in the module
std::optional<GlobalVariable *>
Module::getGlobalVariable(unknown::StringRef GlobalVariableName) const
{
    for (GlobalVariable *GV : mGlobalVariableList)
    {
        if (GV->getName().compare(GlobalVariableName) == 0)
        {
            return GV;
        }
    }

    return {};
}

// Get the specified global variable by address in the module
std::optional<GlobalVariable *>
Module::getGlobalVariable(uint64_t Address) const
{
    for (GlobalVariable *GV : mGlobalVariableList)
    {
        if (GV->getGlobalVariableAddress() == Address)
        {
            return GV;
        }
    }

    return {};
}

////////////////////////////////////////////////////////////
// Insert
// Insert a function into the module
void
Module::insertFunction(Function *Function)
{
    auto It = mFunctionList.find(Function);
    if (It == mFunctionList.end())
    {
        mFunctionList.insert(Function);
    }
}

// Insert a global variable into the module
void
Module::insertGlobalVariable(GlobalVariable *GV)
{
    auto It = mGlobalVariableList.find(GV);
    if (It == mGlobalVariableList.end())
    {
        mGlobalVariableList.insert(GV);
    }
}

////////////////////////////////////////////////////////////
// Print
// Print the module
void
Module::print(unknown::raw_ostream &OS) const
{
    OS << "Module:\n";

    // TODO
}

} // namespace uir
