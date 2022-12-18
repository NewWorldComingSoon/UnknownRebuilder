#pragma once
#include <UnknownIR/Constant.h>

namespace uir {

class GlobalVariable : public Constant
{
public:
    explicit GlobalVariable(Type *Ty, const char *GlobalVariableName);
    virtual ~GlobalVariable();

public:
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

public:
    // Static
    // Generate a new value name by order
    static std::string generateOrderedGlobalVarName(Context &C);
};

} // namespace uir
