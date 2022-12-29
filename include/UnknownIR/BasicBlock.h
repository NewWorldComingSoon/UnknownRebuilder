#pragma once
#include <UnknownIR/Constant.h>

namespace uir {
class Function;
class Instruction;
class TerminatorInstruction;

class BasicBlock : public Constant
{
    friend class TerminatorInstruction;

public:
    using InstListType = std::list<Instruction *>;
    using PredecessorsListType = std::vector<BasicBlock *>;

private:
    std::string mBasicBlockName;
    uint64_t mBasicBlockAddressBegin;
    uint64_t mBasicBlockAddressEnd;
    Function *mParent;
    InstListType mInstList;
    PredecessorsListType mPredecessorsList;

public:
    explicit BasicBlock(Context &C);
    explicit BasicBlock(
        Context &C,
        const unknown::StringRef &BasicBlockName,
        uint64_t BasicBlockAddressBegin = 0,
        uint64_t BasicBlockAddressEnd = 0,
        Function *Parent = nullptr);
    virtual ~BasicBlock();

public:
    // InstList
    const InstListType &getInstList() const { return mInstList; }
    InstListType &getInstList() { return mInstList; }

public:
    // Instruction iterators
    using iterator = InstListType::iterator;
    using const_iterator = InstListType::const_iterator;
    using reverse_iterator = InstListType::reverse_iterator;
    using const_reverse_iterator = InstListType::const_reverse_iterator;

    iterator begin() { return mInstList.begin(); }
    const_iterator begin() const { return mInstList.cbegin(); }
    iterator end() { return mInstList.end(); }
    const_iterator end() const { return mInstList.cend(); }

    reverse_iterator rbegin() { return mInstList.rbegin(); }
    const_reverse_iterator rbegin() const { return mInstList.crbegin(); }
    reverse_iterator rend() { return mInstList.rend(); }
    const_reverse_iterator rend() const { return mInstList.crend(); }

    size_t size() const { return mInstList.size(); }
    bool empty() const { return mInstList.empty(); }
    const Instruction &front() const { return *mInstList.front(); }
    Instruction &front() { return *mInstList.front(); }
    const Instruction &back() const { return *mInstList.back(); }
    Instruction &back() { return *mInstList.back(); }
    void push(Instruction *I) { mInstList.push_back(I); }
    void pop() { mInstList.pop_back(); }
    void push_back(Instruction *I) { mInstList.push_back(I); }
    void pop_back() { mInstList.pop_back(); }
    void push_front(Instruction *I) { mInstList.push_front(I); }
    void pop_front() { mInstList.pop_front(); }
    void insert(iterator I, Instruction *Inst) { mInstList.insert(I, Inst); }
    void insert(iterator I, size_t N, Instruction *Inst) { mInstList.insert(I, N, Inst); }
    void insert(iterator I, iterator First, iterator Last) { mInstList.insert(I, First, Last); }
    void erase(iterator I) { mInstList.erase(I); }
    void erase(iterator First, iterator Last) { mInstList.erase(First, Last); }
    void clear() { mInstList.clear(); }

public:
    // PredecessorsList
    // Returns the list of predecessor of this terminator instruction
    PredecessorsListType &getPredecessorsList() { return mPredecessorsList; }
    const PredecessorsListType &getPredecessorsList() const { return mPredecessorsList; }

public:
    // Predecessors iterators
    using predecessor_iterator = PredecessorsListType::iterator;
    using const_predecessor_iterator = PredecessorsListType::const_iterator;
    predecessor_iterator predecessor_begin();
    const_predecessor_iterator predecessor_begin() const;
    predecessor_iterator predecessor_end();
    const_predecessor_iterator predecessor_end() const;
    BasicBlock *predecessor_back();
    BasicBlock *predecessor_front();
    void predecessor_push(BasicBlock *BB);
    void predecessor_pop();
    size_t predecessor_count() const;
    void predecessor_erase(BasicBlock *BB);
    bool predecessor_empty() const;

public:
    // Get/Set
    // Get the name of this block
    std::string getBasicBlockName() const;

    // Set the name of this block
    void setBasicBlockName(const unknown::StringRef &BlockName);

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

    // Get the terminator instruction of this block
    TerminatorInstruction *getTerminator();

    // Get the terminator instruction of this block
    const TerminatorInstruction *getTerminator() const;

    // Get the first predecessor of this block
    BasicBlock *getFirstPredecessor();

    // Get the first predecessor of this block
    const BasicBlock *getFirstPredecessor() const;

public:
    // Remove/Erase/Insert/Clear
    // Remove the block from the its parent, but does not delete it.
    void removeFromParent();

    // Remove the block from the its parent and delete it.
    void eraseFromParent();

    // Insert an unlinked BasicBlock into a function immediately before/after the specified BasicBlock.
    void insertBeforeOrAfter(BasicBlock *InsertPos, bool Before);

    // Insert an unlinked BasicBlock into a function immediately before the specified BasicBlock.
    void insertBefore(BasicBlock *InsertPos);

    // Insert an unlinked BasicBlock into a function immediately after the specified BasicBlock.
    void insertAfter(BasicBlock *InsertPos);

    // Insert an unlinked instructions into a block
    void insertInst(Instruction *I);

    // Drop all instructions in this block.
    void dropAllReferences();

    // Clear all instructions in this block.
    void clearAllInstructions();

public:
    // Virtual functions
    // Get the readable name of this object
    virtual std::string getReadableName() const override;

    // Print the BasicBlock
    virtual void print(unknown::raw_ostream &OS, bool NewLine = true) const override;

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
        const unknown::StringRef &BasicBlockName,
        uint64_t BasicBlockAddressBegin = 0,
        uint64_t BasicBlockAddressEnd = 0,
        Function *Parent = nullptr);

    // Creates a new BasicBlock.
    static BasicBlock *create(
        Context &C,
        const unknown::StringRef &BasicBlockName,
        uint64_t BasicBlockAddressBegin = 0,
        uint64_t BasicBlockAddressEnd = 0,
        Function *Parent = nullptr);
};

} // namespace uir
