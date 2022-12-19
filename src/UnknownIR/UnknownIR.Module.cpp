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
Module::Module(Context &C, const char *ModuleName) : mContext(C), mModuleName(ModuleName)
{
    //
    //
}

Module::~Module()
{
    //
    //
}

////////////////////////////////////////////////////////////
// FunctionList
// Get function list
const std::unordered_set<Function *> &
Module::getFunctionList() const
{
    return mFunctionList;
}

std::unordered_set<Function *> &
Module::getFunctionList()
{
    return mFunctionList;
}

// Get global variable list
const std::unordered_set<GlobalVariable *> &
Module::getGlobalVariableList() const
{
    return mGlobalVariableList;
}

std::unordered_set<GlobalVariable *> &
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
Module::setModuleName(const char *ModuleName)
{
    mModuleName = ModuleName;
}

// Get the specified function in the module
Function *
Module::getFunction(const char *FunctionName) const
{
    for (Function *Func : mFunctionList)
    {
        if (Func->getName().compare(FunctionName) == 0)
        {
            return Func;
        }
    }

    return nullptr;
}

// Get the specified function by address in the module
Function *
Module::getFunction(uint64_t Address) const
{
    for (Function *Func : mFunctionList)
    {
        if (Func->getFunctionBeginAddress() == Address)
        {
            return Func;
        }
    }
    return nullptr;
}

// Get the specified global variable by name in the module
GlobalVariable *
Module::getGlobalVariable(const char *GlobalVariableName) const
{
    for (GlobalVariable *GV : mGlobalVariableList)
    {
        if (GV->getName().compare(GlobalVariableName) == 0)
        {
            return GV;
        }
    }

    return nullptr;
}

// Get the specified global variable by address in the module
GlobalVariable *
Module::getGlobalVariable(uint64_t Address) const
{
    for (GlobalVariable *GV : mGlobalVariableList)
    {
        if (GV->getGlobalVariableAddress() == Address)
        {
            return GV;
        }
    }

    return nullptr;
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

} // namespace uir
