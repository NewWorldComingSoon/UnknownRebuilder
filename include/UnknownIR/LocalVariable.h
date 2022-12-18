#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class Context;

class LocalVariable : public Constant
{
public:
    explicit LocalVariable(Type *Ty, const char *LocalVariableName);
    virtual ~LocalVariable();

public:
    // Static
    // Generate a new value name by order
    static std::string generateOrderedLocalVarName(Context &C);
};

} // namespace uir
