#pragma once
#include <UnknownIR/Constant.h>

namespace uir {
class Function;
class Instruction;

class BasicBlock : public Constant
{
public:
    using InstListType = std::list<Instruction *>;

private:
    std::string mBasicBlockName;
    uint64_t mBasicBlockAddressBegin;
    uint64_t mBasicBlockAddressEnd;
    Function *mParent;
    InstListType mInstList;

public:
    explicit BasicBlock(Context &C);
    explicit BasicBlock(
        Context &C,
        unknown::StringRef BasicBlockName,
        uint64_t BasicBlockAddressBegin,
        uint64_t BasicBlockAddressEnd,
        Function *Parent = nullptr);
    virtual ~BasicBlock();

public:
    // BasicBlock
    const InstListType &getInstList() const { return mInstList; }
    InstListType &getInstList() { return mInstList; }

public:
    // Instruction iterators
    using iterator = InstListType::iterator;
    using const_iterator = InstListType::const_iterator;
    using reverse_iterator = InstListType::reverse_iterator;
    using const_reverse_iterator = InstListType::const_reverse_iterator;

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

    // Print the BasicBlock
    virtual void print(unknown::raw_ostream &OS) const;

public:
    // Static
    // Generate a new block name by order
    static std::string generateOrderedBasicBlockName(Context &C);
};

} // namespace uir
