#pragma once
#include "Constant.h"

namespace uir {

class GlobalVariable : public Constant
{
public:
    GlobalVariable(Type *Ty, const std::string GlobalVariableName);
    virtual ~GlobalVariable();
};

} // namespace uir
