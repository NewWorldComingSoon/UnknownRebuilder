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
        const unknown::StringRef &FunctionName = "",
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
    // AttributesList
    const FunctionAttributesListType &getFunctionAttributesList() const { return mFunctionAttributesList; }
    FunctionAttributesListType &getFunctionAttributesList() { return mFunctionAttributesList; }

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
    void clear() { mBasicBlocksList.clear(); }

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
    void arg_clear() { mArgumentsList.clear(); }

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
    void fc_push_back(FunctionContext *FC) { mFunctionContextList.push_back(FC); }
    void fc_push_front(FunctionContext *FC) { mFunctionContextList.push_front(FC); }
    void fc_pop_back() { mFunctionContextList.pop_back(); }
    void fc_pop_front() { mFunctionContextList.pop_front(); }
    void fc_clear() { mFunctionContextList.clear(); }

public:
    // Attributes iterators
    using attr_iterator = FunctionAttributesListType::iterator;
    using const_attr__iterator = FunctionAttributesListType::const_iterator;
    attr_iterator attr_begin() { return mFunctionAttributesList.begin(); }
    const_attr__iterator attr_begin() const { return mFunctionAttributesList.cbegin(); }
    attr_iterator attr_end() { return mFunctionAttributesList.end(); }
    const_attr__iterator attr_end() const { return mFunctionAttributesList.cend(); }

    size_t attr_size() const { return mFunctionAttributesList.size(); }
    bool attr_empty() const { return mFunctionAttributesList.empty(); }
    const std::string &attr_front() const { return mFunctionAttributesList.front(); }
    std::string &attr_front() { return mFunctionAttributesList.front(); }
    const std::string &attr_back() const { return mFunctionAttributesList.back(); }
    std::string &attr_back() { return mFunctionAttributesList.back(); }
    void attr_push_back(const std::string &Attr) { mFunctionAttributesList.push_back(Attr); }
    void attr_pop_back() { mFunctionAttributesList.pop_back(); }
    void attr_erase(attr_iterator It) { mFunctionAttributesList.erase(It); }
    void attr_clear() { mFunctionAttributesList.clear(); }

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
    // Function Attribute
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

    // Insert a new arg to this function
    void insertArgument(Argument *Arg);

    // Insert a new function context to this function
    void insertFunctionContext(FunctionContext *FC);

    // Drop all blocks in this function.
    void dropAllReferences();

    // Clear all basic blocks.
    void clearAllBasicBlock();

public:
    // Static
    // Generate a new function name by order
    static std::string generateOrderedFunctionName(Context &C);

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

    // Get the property 'f' of the value
    virtual unknown::StringRef getPropertyFunction() const;

    // Get the property 'attributes' of the value
    virtual unknown::StringRef getPropertyAttributes() const;

    // Get the property 'arguments' of the value
    virtual unknown::StringRef getPropertyArguments() const;

    // Get the property 'context' of the value
    virtual unknown::StringRef getPropertyContext() const;

    // Print the function
    virtual void print(unknown::raw_ostream &OS, bool NewLine = true) const override;

    // Print the function
    virtual void print(unknown::XMLPrinter &Printer) const;

public:
    static Function *
    get(Context &C,
        const unknown::StringRef &FunctionName = "",
        Module *Parent = nullptr,
        uint64_t FunctionAddressBegin = 0,
        uint64_t FunctionAddressEnd = 0);
};

} // namespace uir
