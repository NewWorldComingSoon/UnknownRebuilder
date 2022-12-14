#pragma once
#include "Constant.h"

namespace uir {

class Context;

class LocalVariable : public Constant
{
public:
    explicit LocalVariable(Type *Ty, const std::string LocalVariableName);
    virtual ~LocalVariable();

public:
    // Static
    // Generate a new value name by order
    static std::string generateOrderedLocalVarName(Context &C);
};

} // namespace uir
