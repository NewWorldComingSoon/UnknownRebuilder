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
Module::Module(Context &C, const unknown::StringRef &ModuleName) : mContext(C), mModuleName(ModuleName)
{
    // Clear all the name index
    C.mImpl->clearOrderedNameIndex();
}

Module::~Module()
{
    clearAllFunctions();
    clearAllGlobalVariables();
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
Module::setModuleName(const unknown::StringRef &ModuleName)
{
    mModuleName = ModuleName;
}

// Get the readable name of this object
std::string
Module::getReadableName() const
{
    // module.mod1
    std::string ReadableName = UIR_MODULE_VARIABLE_NAME_PREFIX;
    ReadableName += mModuleName;

    return ReadableName;
}

// Get the specified function in the module
std::optional<Function *>
Module::getFunction(const unknown::StringRef &FunctionName) const
{
    for (auto Func : mFunctionList)
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
    for (auto Func : mFunctionList)
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
Module::getGlobalVariable(const unknown::StringRef &GlobalVariableName) const
{
    for (auto GV : mGlobalVariableList)
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
    for (auto GV : mGlobalVariableList)
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
    push_back(Function);
    Function->setParent(this);
}

// Insert a global variable into the module
void
Module::insertGlobalVariable(GlobalVariable *GV)
{
    global_push_back(GV);
    GV->setParent(this);
}

// Drop all functions/global variables in this module.
void
Module::dropAllReferences()
{
    for (auto F : *this)
    {
        if (F)
        {
            F->dropAllReferences();
        }
    }

    for (auto It = global_begin(); It != global_end(); ++It)
    {
        auto GV = *It;
        if (GV)
        {
            GV->dropAllReferences();
        }
    }
}

// Clear all functions in this module.
void
Module::clearAllFunctions()
{
    for (auto F : *this)
    {
        if (F)
        {
            F->dropAllReferences();
        }
    }

    // Clear all functions
    for (auto F : *this)
    {
        if (F)
        {
            F->clearAllBasicBlock();
        }
    }

    // Free all functions
    std::vector<Function *> FreeFunctionList;
    for (auto F : *this)
    {
        if (F)
        {
            if (std::find(FreeFunctionList.begin(), FreeFunctionList.end(), F) == FreeFunctionList.end())
            {
                FreeFunctionList.push_back(F);
                delete F;
            }
        }
    }

    // Clear list
    clear();
}

// Clear all global variables in this module.
void
Module::clearAllGlobalVariables()
{
    for (auto It = global_begin(); It != global_end(); ++It)
    {
        auto GV = *It;
        if (GV)
        {
            GV->dropAllReferences();
        }
    }

    // Free all global variables
    std::vector<GlobalVariable *> FreeGVList;
    for (auto It = global_begin(); It != global_end(); ++It)
    {
        auto GV = *It;
        if (GV)
        {
            if (std::find(FreeGVList.begin(), FreeGVList.end(), GV) == FreeGVList.end())
            {
                FreeGVList.push_back(GV);
                delete GV;
            }
        }
    }

    // Clear list
    global_clear();
}

////////////////////////////////////////////////////////////
// Virtual functions
// Get the property 'module' of the value
unknown::StringRef
Module::getPropertyModule() const
{
    return "module";
}

// Get the property 'name' of the value
unknown::StringRef
Module::getPropertyName() const
{
    return "name";
}

// Get the property 'arch' of the value
unknown::StringRef
Module::getPropertyArch() const
{
    return "arch";
}

// Get the property 'mode' of the value
unknown::StringRef
Module::getPropertyMode() const
{
    return "mode";
}

////////////////////////////////////////////////////////////
// Print
// Print the module
void
Module::print(unknown::raw_ostream &OS, bool NewLine) const
{
    unknown::XMLPrinter Printer;
    print(Printer);
    OS << Printer.CStr();
}

// Print the module
void
Module::print(unknown::XMLPrinter &Printer) const
{
    Printer.OpenElement(getPropertyModule().str().c_str());

    // name
    {
        Printer.PushAttribute(getPropertyName().str().c_str(), getReadableName().c_str());
    }

    // arch
    {
        Printer.PushAttribute(getPropertyArch().str().c_str(), mContext.getArchString().str().c_str());
    }

    // mode
    {
        Printer.PushAttribute(getPropertyMode().str().c_str(), mContext.getModeString().str().c_str());
    }

    // gv
    for (auto It = global_begin(); It != global_end(); ++It)
    {
        auto GV = *It;
        if (GV == nullptr)
        {
            continue;
        }

        GV->print(Printer);
    }

    // function
    for (auto F : *this)
    {
        if (F == nullptr)
        {
            continue;
        }

        F->print(Printer);
    }

    Printer.CloseElement();
}

} // namespace uir
