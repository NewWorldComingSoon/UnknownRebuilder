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

} // namespace uir
