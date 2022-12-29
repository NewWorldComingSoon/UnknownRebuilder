#pragma once
#include <UnknownIR/Constant.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>

namespace uir {

class Module;
class BasicBlock;
class Argument;
class FunctionContext;

class Function : public Constant
{
public:
    using BasicBlockListType = std::list<BasicBlock *>;
    using ArgumentListType = std::list<Argument *>;
    using FunctionContextListType = std::list<FunctionContext *>;
    using FunctionAttributesListType = std::vector<std::string>;

private:
    Module *mParent;
    std::string mFunctionName;
    uint64_t mFunctionAddressBegin;
    uint64_t mFunctionAddressEnd;
    BasicBlockListType mBasicBlocksList;
    ArgumentListType mArgumentsList;
    FunctionContextListType mFunctionContextList;
    FunctionAttributesListType mFunctionAttributesList;

public:
    explicit Function(
        Context &C,
        const unknown::StringRef &FunctionName,
        Module *Parent = nullptr,
        uint64_t FunctionAddressBegin = 0,
        uint64_t FunctionAddressEnd = 0);
    virtual ~Function();

public:
    // BasicBlocksList
    const BasicBlockListType &getBasicBlockList() const { return mBasicBlocksList; }
    BasicBlockListType &getBasicBlockList() { return mBasicBlocksList; }

public:
    // ArgumentsList
    const ArgumentListType &getArgumentList() const { return mArgumentsList; }
    ArgumentListType &getArgumentList() { return mArgumentsList; }

public:
    // FunctionContextList
    const FunctionContextListType &getFunctionContextList() const { return mFunctionContextList; }
    FunctionContextListType &getFunctionContextList() { return mFunctionContextList; }

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
    void push_back(BasicBlock *BB) { mBasicBlocksList.push_back(BB); }
    void push_front(BasicBlock *BB) { mBasicBlocksList.push_front(BB); }
    void pop_back() { mBasicBlocksList.pop_back(); }
    void pop_front() { mBasicBlocksList.pop_front(); }

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
    void arg_push_back(Argument *Arg) { mArgumentsList.push_back(Arg); }
    void arg_push_front(Argument *Arg) { mArgumentsList.push_front(Arg); }
    void arg_pop_back() { mArgumentsList.pop_back(); }
    void arg_pop_front() { mArgumentsList.pop_front(); }

public:
    // FunctionContext iterators
    using fc_iterator = FunctionContextListType::iterator;
    using const_fc_iterator = FunctionContextListType::const_iterator;
    fc_iterator fc_begin() { return mFunctionContextList.begin(); }
    const_fc_iterator fc_begin() const { return mFunctionContextList.cbegin(); }
    fc_iterator fc_end() { return mFunctionContextList.end(); }
    const_fc_iterator fc_end() const { return mFunctionContextList.cend(); }

    size_t fc_size() const { return mFunctionContextList.size(); }
    bool fc_empty() const { return mFunctionContextList.empty(); }
    const FunctionContext &fc_front() const { return *mFunctionContextList.front(); }
    FunctionContext &fc_front() { return *mFunctionContextList.front(); }
    const FunctionContext &fc_back() const { return *mFunctionContextList.back(); }
    FunctionContext &fc_back() { return *mFunctionContextList.back(); }

public:
    // Get/Set
    // Get parent module
    const Module *getParent() const;
    Module *getParent();

    // Set parent module
    void setParent(Module *Parent);

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

    // Get the name of this function
    const std::string getFunctionName() const;

    // Set the name of this function
    void setFunctionName(const unknown::StringRef &FunctionName);

    // Get the attributes of this function
    const FunctionAttributesListType &getFunctionAttributes() const;

    // Set the attributes of this function
    void setFunctionAttributes(const FunctionAttributesListType &FunctionAttributes);

public:
    // Add/Remove/Has
    // Add function attribute to this function.
    void addFnAttr(const unknown::StringRef &FunctionAttribute);

    // Remove function attribute from this function.
    void removeFnAttr(const unknown::StringRef &FunctionAttribute);

    // Check if this function has a specific attribute.
    bool hasFnAttr(const unknown::StringRef &FunctionAttribute) const;

public:
    // Remove/Erase/Insert/Clear
    // Remove the function from the its parent, but does not delete it.
    void removeFromParent();

    // Remove the function from the its parent and delete it.
    void eraseFromParent();

    // Insert a new basic block to this function
    void insertBasicBlock(BasicBlock *BB);

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
