#pragma once
#include <unordered_set>

#include <UnknownIR/Function.h>

namespace uir {

class Module
{
protected:
    Context &mContext;
    std::string mModuleName;
    std::unordered_set<Function *> mFunctionList;

public:
    explicit Module(Context &C, const char *ModuleName);
    virtual ~Module();

public:
    // Context
    Context &getContext() const;

public:
    // Get/Set
    // Get/Set the name of module
    std::string getModuleName() const;
    void setModuleName(const char *ModuleName);

    // Get the specified function by name in the module
    Function *getFunction(const char *FunctionName) const;
};

} // namespace uir
