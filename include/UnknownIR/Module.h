#pragma once
#include <UnknownIR/Function.h>

namespace uir {

class Module
{
protected:
    Context &mContext;
    std::string mModuleName;

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
};

} // namespace uir
