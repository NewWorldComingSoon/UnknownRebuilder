#pragma once
#include <UnknownIR/Constant.h>

namespace uir {
class Function;

class BasicBlock : public Constant
{
private:
    std::string mBasicBlockName;
    uint64_t mBasicBlockAddressBegin;
    uint64_t mBasicBlockAddressEnd;
    Function *mParent;

public:
    explicit BasicBlock(
        Context &C,
        const char *BasicBlockName,
        uint64_t BasicBlockAddressBegin,
        uint64_t BasicBlockAddressEnd,
        Function *Parent = nullptr);
    virtual ~BasicBlock();

public:
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

public:
    // Static
    // Generate a new block name by order
    static std::string generateOrderedBasicBlockName(Context &C);
};

} // namespace uir
