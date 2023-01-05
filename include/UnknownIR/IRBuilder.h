#pragma once
#include <UnknownIR/Instruction.h>
#include <UnknownIR/BasicBlock.h>

namespace uir {

class IRBuilderDefaultInserter
{
protected:
    void InsertHelper(Instruction *I, uint64_t InstAddress, BasicBlock *BB, BasicBlock::iterator InsertPt) const;
};

class IRBuilderBase
{
protected:
    BasicBlock *mBB;
    BasicBlock::iterator mInsertPt;
    Context &mContext;

public:
    IRBuilderBase(Context &C);

public:
    // Get/Set
    Context &getContext() const { return mContext; }
    BasicBlock *getInsertBlock() const { return mBB; }
    BasicBlock::iterator getInsertPoint() const { return mInsertPt; }

public:
    // Insertion Point
    // Clear the insertion point
    void clearInsertionPoint();

    // Set the insertion point
    void setInsertPoint(BasicBlock *BB);
    void setInsertPoint(Instruction *I);
};

} // namespace uir
