#pragma once
#include "Value.h"

namespace uir {

class LocalVariable : public Value
{
public:
    explicit LocalVariable(Type *Ty, const std::string LocalVariableName);
    virtual ~LocalVariable();
};

} // namespace uir
