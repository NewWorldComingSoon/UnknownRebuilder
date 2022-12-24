#pragma once
#include <UnknownIR/Constant.h>

namespace uir {
class Function;
class Instruction;

class BasicBlock : public Constant
{
    friend class TerminatorInst;

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
        uint64_t BasicBlockAddressBegin = 0,
        uint64_t BasicBlockAddressEnd = 0,
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
    // Get/Set
    // Get the name of this block
    std::string getBasicBlockName() const;

    // Set the name of this block
    void setBasicBlockName(unknown::StringRef BlockName);

    // Get the parent of this block
    const Function *getParent() const;

    // Get the parent of this block
    Function *getParent();

    // Set the parent of this block
    void setParent(Function *F);

    // Get the begin address of this block
    uint64_t getBasicBlockAddressBegin() const;

    // Get the end address of this block
    uint64_t getBasicBlockAddressEnd() const;

    // Set the begin address of this block
    void setBasicBlockAddressBegin(uint64_t BasicBlockAddressBegin);

    // Set the end address of this block
    void setBasicBlockAddressEnd(uint64_t BasicBlockAddressEnd);

    // Get the size of this block
    uint64_t getBasicBlockSize() const;

    // Returns the terminator instruction
    TerminatorInst *getTerminator();
    const TerminatorInst *getTerminator() const;

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

    // Creates a new BasicBlock.
    static BasicBlock *get(Context &C);

    // Creates a new BasicBlock.
    static BasicBlock *create(Context &C);

    // Creates a new BasicBlock.
    static BasicBlock *
    get(Context &C,
        unknown::StringRef BasicBlockName,
        uint64_t BasicBlockAddressBegin = 0,
        uint64_t BasicBlockAddressEnd = 0,
        Function *Parent = nullptr);

    // Creates a new BasicBlock.
    static BasicBlock *create(
        Context &C,
        unknown::StringRef BasicBlockName,
        uint64_t BasicBlockAddressBegin = 0,
        uint64_t BasicBlockAddressEnd = 0,
        Function *Parent = nullptr);
};

} // namespace uir
