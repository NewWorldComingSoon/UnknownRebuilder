#pragma once
#include "Constant.h"

namespace uir {

class Function : public Constant
{
private:
    std::string mFunctionName;
    uint64_t mFunctionAddress;

public:
    explicit Function(Context &C, const std::string FunctionName, uint64_t FunctionAddress);
    virtual ~Function();

public:
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

public:
    // Static
    // Generate a new function name by order
    static std::string generateOrderedFunctionName(Context &C);
};

} // namespace uir
