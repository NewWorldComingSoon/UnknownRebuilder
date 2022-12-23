#pragma once
#include <UnknownIR/Constant.h>

namespace uir {
class Function;
class Instruction;

class BasicBlock : public Constant
{
private:
    std::string mBasicBlockName;
    uint64_t mBasicBlockAddressBegin;
    uint64_t mBasicBlockAddressEnd;
    Function *mParent;
    std::vector<Instruction *> mInstList;

public:
    explicit BasicBlock(Context &C);
    explicit BasicBlock(
        Context &C,
        const char *BasicBlockName,
        uint64_t BasicBlockAddressBegin,
        uint64_t BasicBlockAddressEnd,
        Function *Parent = nullptr);
    virtual ~BasicBlock();

public:
    // Instruction iterators
    using iterator = std::vector<Instruction *>::iterator;
    using const_iterator = std::vector<Instruction *>::const_iterator;
    using reverse_iterator = std::vector<Instruction *>::reverse_iterator;
    using const_reverse_iterator = std::vector<Instruction *>::const_reverse_iterator;

    iterator begin() { return mInstList.begin(); }
    const_iterator begin() const { return mInstList.begin(); }
    iterator end() { return mInstList.end(); }
    const_iterator end() const { return mInstList.end(); }

    reverse_iterator rbegin() { return mInstList.rbegin(); }
    const_reverse_iterator rbegin() const { return mInstList.rbegin(); }
    reverse_iterator rend() { return mInstList.rend(); }
    const_reverse_iterator rend() const { return mInstList.rend(); }

    size_t size() const { return mInstList.size(); }
    bool empty() const { return mInstList.empty(); }
    const Instruction &front() const { return *mInstList.front(); }
    Instruction &front() { return *mInstList.front(); }
    const Instruction &back() const { return *mInstList.back(); }
    Instruction &back() { return *mInstList.back(); }

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

public:
    // Static
    // Generate a new block name by order
    static std::string generateOrderedBasicBlockName(Context &C);
};

} // namespace uir
