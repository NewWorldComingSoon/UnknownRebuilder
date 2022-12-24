#pragma once
#include <UnknownIR/InstructionBase.h>
#include <UnknownIR/Constant.h>

namespace uir {

class TerminatorInst : public Instruction
{
public:
    using SuccessorsListType = std::vector<BasicBlock *>;

protected:
    SuccessorsListType mSuccessorsList;

protected:
    TerminatorInst(OpCodeID OpCodeId);
    virtual ~TerminatorInst();

public:
    // SuccessorsList
    // Returns the list of successors of this terminator instruction
    SuccessorsListType &getSuccessorsList() { return mSuccessorsList; }
    const SuccessorsListType &getSuccessorsList() const { return mSuccessorsList; }

public:
    // Iterator
    using successor_iterator = SuccessorsListType::iterator;
    using const_successor_iterator = SuccessorsListType::const_iterator;
    successor_iterator successor_begin();
    const_successor_iterator successor_begin() const;
    successor_iterator successor_end();
    const_successor_iterator successor_end() const;
    BasicBlock *successor_back();
    BasicBlock *successor_front();
    void successor_push(BasicBlock *BB);
    void successor_pop();
    size_t successor_count() const;
    void successor_erase(BasicBlock *BB);
    bool successor_empty() const;
};

} // namespace uir
