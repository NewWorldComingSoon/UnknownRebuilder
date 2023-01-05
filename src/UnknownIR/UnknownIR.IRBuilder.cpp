#include <IRBuilder.h>

namespace uir {
////////////////////////////////////////////////////////////
//     IRBuilderDefaultInserter
//
void
IRBuilderDefaultInserter::InsertHelper(
    Instruction *I,
    uint64_t InstAddress,
    BasicBlock *BB,
    BasicBlock::iterator InsertPt) const
{
    if (I)
    {
        I->setInstructionAddress(InstAddress);
    }

    if (BB)
    {
        BB->getInstList().insert(InsertPt, I);
        if (I)
        {
            I->setParent(BB);
        }
    }
}

////////////////////////////////////////////////////////////
//     IRBuilderBase
//
IRBuilderBase::IRBuilderBase(Context &C) : mContext(C)
{
    clearInsertionPoint();
}

////////////////////////////////////////////////////////////
// Get/Set
Context &
IRBuilderBase::getContext() const
{
    return mContext;
}

BasicBlock *
IRBuilderBase::getInsertBlock() const
{
    return mBB;
}

BasicBlock::iterator
IRBuilderBase::getInsertPoint() const
{
    return mInsertPt;
}

////////////////////////////////////////////////////////////
// Insertion Point
// Clear the insertion point
void
IRBuilderBase::clearInsertionPoint()
{
    mBB = nullptr;
    (*mInsertPt) = nullptr;
}

// Set the insertion point
void
IRBuilderBase::setInsertPoint(BasicBlock *BB)
{
    assert(BB != nullptr && "BB != nullptr");

    mBB = BB;
    mInsertPt = BB->end();
}

void
IRBuilderBase::setInsertPoint(Instruction *I)
{
    assert(I != nullptr && "I != nullptr");

    auto BB = I->getParent();
    assert(BB != nullptr && "BB != nullptr");

    mBB = BB;

    for (auto It = BB->begin(); It != BB->end(); ++It)
    {
        if ((*It) == I)
        {
            mInsertPt = It;
            return;
        }
    }
}

void
IRBuilderBase::setInsertPoint(BasicBlock *BB, BasicBlock::iterator IT)
{
    assert(BB != nullptr && "BB != nullptr");

    mBB = BB;
    mInsertPt = IT;
}

////////////////////////////////////////////////////////////
//     IRBuilder
//
IRBuilder::IRBuilder(Context &C) : IRBuilderBase(C) {}

IRBuilder::IRBuilder(BasicBlock *BB) : IRBuilder(BB->getContext())
{
    setInsertPoint(BB);
}

IRBuilder::IRBuilder(Instruction *I) : IRBuilder(I->getContext())
{
    setInsertPoint(I);
}

IRBuilder::IRBuilder(BasicBlock *BB, BasicBlock::iterator IT) : IRBuilder(BB->getContext())
{
    setInsertPoint(BB, IT);
}

////////////////////////////////////////////////////////////
// Create
// Return
ReturnInstruction *
IRBuilder::createRetVoid(uint64_t InstAddress)
{
    return insert(ReturnInstruction::get(), InstAddress);
}

ReturnImmInstruction *
IRBuilder::createRetImm(ConstantInt *ImmConstantInt, uint64_t InstAddress)
{
    return insert(ReturnImmInstruction::get(ImmConstantInt), InstAddress);
}

} // namespace uir
