#pragma once
#include <UnknownIR/Constant.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class BasicBlock;

class Function : public Constant
{
public:
    using BasicBlockListType = std::list<BasicBlock *>;

private:
    std::string mFunctionName;
    uint64_t mFunctionAddressBegin;
    uint64_t mFunctionAddressEnd;
    BasicBlockListType mBasicBlocksList;

public:
    explicit Function(
        Context &C,
        unknown::StringRef FunctionName,
        uint64_t FunctionAddressBegin = 0,
        uint64_t FunctionAddressEnd = 0);
    virtual ~Function();

public:
    // BasicBlocksList
    const BasicBlockListType &getBasicBlockList() const { return mBasicBlocksList; }
    BasicBlockListType &getBasicBlockList() { return mBasicBlocksList; }

public:
    // BasicBlock iterators
    using iterator = BasicBlockListType::iterator;
    using const_iterator = BasicBlockListType::const_iterator;
    iterator begin() { return mBasicBlocksList.begin(); }
    const_iterator begin() const { return mBasicBlocksList.cbegin(); }
    iterator end() { return mBasicBlocksList.end(); }
    const_iterator end() const { return mBasicBlocksList.cend(); }

    size_t size() const { return mBasicBlocksList.size(); }
    bool empty() const { return mBasicBlocksList.empty(); }
    const BasicBlock &front() const { return *mBasicBlocksList.front(); }
    BasicBlock &front() { return *mBasicBlocksList.front(); }
    const BasicBlock &back() const { return *mBasicBlocksList.back(); }
    BasicBlock &back() { return *mBasicBlocksList.back(); }

public:
    // Get/Set
    // Get the begin/end address of this function
    uint64_t getFunctionBeginAddress() const;
    uint64_t getFunctionEndAddress() const;

    // Set the begin/end address of this function
    void setFunctionBeginAddress(uint64_t FunctionBeginAddress);
    void setFunctionEndAddress(uint64_t FunctionEndAddress);

public:
    // Static
    // Generate a new function name by order
    static std::string generateOrderedFunctionName(Context &C);

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

    // Print the function
    void print(unknown::raw_ostream &OS) const;
};

} // namespace uir
