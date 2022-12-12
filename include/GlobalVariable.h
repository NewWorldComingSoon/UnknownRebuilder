#pragma once
#include "Constant.h"

namespace uir {

class GlobalVariable : public Constant
{
public:
    explicit GlobalVariable(Type *Ty, const std::string GlobalVariableName);
    virtual ~GlobalVariable();

public:
    // Get the readable name of this object
    virtual std::string getReadableName() const override;
};

} // namespace uir
