#pragma once
#include <UnknownIR/Constant.h>
#include <UnknownIR/Argument.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class BasicBlock;

class Function : public Constant
{
public:
    using BasicBlockListType = std::list<BasicBlock *>;
    using ArgumentListType = std::list<Argument *>;

private:
    std::string mFunctionName;
    uint64_t mFunctionAddressBegin;
    uint64_t mFunctionAddressEnd;
    BasicBlockListType mBasicBlocksList;
    ArgumentListType mArgumentsList;

public:
    explicit Function(
        Context &C,
        const unknown::StringRef &FunctionName,
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
    // Argument iterators
    using arg_iterator = ArgumentListType::iterator;
    using const_arg_iterator = ArgumentListType::const_iterator;
    arg_iterator arg_begin() { return mArgumentsList.begin(); }
    const_arg_iterator arg_begin() const { return mArgumentsList.cbegin(); }
    arg_iterator arg_end() { return mArgumentsList.end(); }
    const_arg_iterator arg_end() const { return mArgumentsList.cend(); }

    size_t arg_size() const { return mArgumentsList.size(); }
    bool arg_empty() const { return mArgumentsList.empty(); }
    const Argument &arg_front() const { return *mArgumentsList.front(); }
    Argument &arg_front() { return *mArgumentsList.front(); }
    const Argument &arg_back() const { return *mArgumentsList.back(); }
    Argument &arg_back() { return *mArgumentsList.back(); }

public:
    // Get/Set
    // Get the begin/end address of this function
    uint64_t getFunctionBeginAddress() const;

    // Get the begin/end address of this function
    uint64_t getFunctionEndAddress() const;

    // Set the begin address of this function
    void setFunctionBeginAddress(uint64_t FunctionBeginAddress);

    // Set the end address of this function
    void setFunctionEndAddress(uint64_t FunctionEndAddress);

    // Get the entry block of this function
    const BasicBlock &getEntryBlock() const;

    // Get the entry block of this function
    BasicBlock &getEntryBlock();

public:
    // Static
    // Generate a new function name by order
    static std::string generateOrderedFunctionName(Context &C);

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

    // Print the function
    virtual void print(unknown::raw_ostream &OS, bool NewLine = true) const override;
};

} // namespace uir
