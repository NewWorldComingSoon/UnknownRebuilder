#pragma once
#include "Constant.h"

namespace uir {

class LocalVariable : public Constant
{
public:
    explicit LocalVariable(Type *Ty, const std::string LocalVariableName);
    virtual ~LocalVariable();
};

} // namespace uir
