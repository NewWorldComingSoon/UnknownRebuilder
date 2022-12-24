#include <BasicBlock.h>
#include <Instruction.h>
#include <Function.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     BasicBlock
//
BasicBlock::BasicBlock(Context &C) : BasicBlock(C, BasicBlock::generateOrderedBasicBlockName(C), 0, 0)
{
    //
    //
}

BasicBlock::BasicBlock(
    Context &C,
    unknown::StringRef BasicBlockName,
    uint64_t BasicBlockAddressBegin,
    uint64_t BasicBlockAddressEnd,
    Function *Parent /*= nullptr*/) :
    Constant(Type::getLabelTy(C), BasicBlockName),
    mBasicBlockName(BasicBlockName),
    mBasicBlockAddressBegin(BasicBlockAddressBegin),
    mBasicBlockAddressEnd(BasicBlockAddressEnd),
    mParent(Parent)
{
    //
    //
}

BasicBlock::~BasicBlock()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Predecessors iterators
BasicBlock::predecessor_iterator
BasicBlock::predecessor_begin()
{
    return mPredecessorsList.begin();
}

BasicBlock::const_predecessor_iterator
BasicBlock::predecessor_begin() const
{
    return mPredecessorsList.cbegin();
}

BasicBlock::predecessor_iterator
BasicBlock::predecessor_end()
{
    return mPredecessorsList.end();
}

BasicBlock::const_predecessor_iterator
BasicBlock::predecessor_end() const
{
    return mPredecessorsList.cend();
}

BasicBlock *
BasicBlock::predecessor_back()
{
    return mPredecessorsList.back();
}

BasicBlock *
BasicBlock::predecessor_front()
{
    return mPredecessorsList.front();
}

void
BasicBlock::predecessor_push(BasicBlock *BB)
{
    mPredecessorsList.push_back(BB);
}

void
BasicBlock::predecessor_pop()
{
    mPredecessorsList.pop_back();
}

size_t
BasicBlock::predecessor_count() const
{
    return mPredecessorsList.size();
}

void
BasicBlock::predecessor_erase(BasicBlock *BB)
{
    for (auto It = mPredecessorsList.begin(); It != mPredecessorsList.end(); ++It)
    {
        if (*It == BB)
        {
            mPredecessorsList.erase(It);
            break;
        }
    }
}

bool
BasicBlock::predecessor_empty() const
{
    return mPredecessorsList.empty();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the name of block
std::string
BasicBlock::getBasicBlockName() const
{
    return mBasicBlockName;
}

// Set the name of block
void
BasicBlock::setBasicBlockName(unknown::StringRef BlockName)
{
    mBasicBlockName = BlockName;
}

// Get the parent of this block
const Function *
BasicBlock::getParent() const
{
    return mParent;
}

// Get the parent of this block
Function *
BasicBlock::getParent()
{
    return mParent;
}

// Set the parent of this block
void
BasicBlock::setParent(Function *F)
{
    mParent = F;
}

// Get the begin address of this block
uint64_t
BasicBlock::getBasicBlockAddressBegin() const
{
    return mBasicBlockAddressBegin;
}

// Get the end address of this block
uint64_t
BasicBlock::getBasicBlockAddressEnd() const
{
    return mBasicBlockAddressEnd;
}

// Set the begin address of this block
void
BasicBlock::setBasicBlockAddressBegin(uint64_t BasicBlockAddressBegin)
{
    mBasicBlockAddressBegin = BasicBlockAddressBegin;
}

// Set the end address of this block
void
BasicBlock::setBasicBlockAddressEnd(uint64_t BasicBlockAddressEnd)
{
    mBasicBlockAddressEnd = BasicBlockAddressEnd;
}

// Get the size of this block
uint64_t
BasicBlock::getBasicBlockSize() const
{
    return mBasicBlockAddressEnd - mBasicBlockAddressBegin;
}

// Get the terminator instruction of this block
TerminatorInst *
BasicBlock::getTerminator()
{
    if (empty())
    {
        return nullptr;
    }

    return dynamic_cast<TerminatorInst *>(*rbegin());
}

// Get the terminator instruction of this block
const TerminatorInst *
BasicBlock::getTerminator() const
{
    if (empty())
    {
        return nullptr;
    }

    return dynamic_cast<const TerminatorInst *>(*rbegin());
}

// Get the first predecessor of this block
BasicBlock *
BasicBlock::getFirstPredecessor()
{
    return *predecessor_begin();
}

// Get the first predecessor of this block
const BasicBlock *
BasicBlock::getFirstPredecessor() const
{
    return *predecessor_begin();
}

////////////////////////////////////////////////////////////
// Remove/Erase/Insert
// Remove the block from the its parent, but does not delete it.
void
BasicBlock::removeFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    mParent->getBasicBlockList().remove(this);
}

// Remove the block from the its parent and delete it.
void
BasicBlock::eraseFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    for (auto It = mParent->getBasicBlockList().begin(); It != mParent->getBasicBlockList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getBasicBlockList().erase(It);
            break;
        }
    }
}

// Insert an unlinked BasicBlock into a function immediately before the specified BasicBlock.
void
BasicBlock::insertBefore(BasicBlock *InsertPos)
{
    if (InsertPos->getParent() == nullptr)
    {
        return;
    }

    auto InsertPosIt = InsertPos->getParent()->getBasicBlockList().begin();
    for (; InsertPosIt != InsertPos->getParent()->getBasicBlockList().end(); ++InsertPosIt)
    {
        if (*InsertPosIt == InsertPos)
        {
            break;
        }
    }

    InsertPos->getParent()->getBasicBlockList().insert(InsertPosIt, this);
}

// Insert an unlinked BasicBlock into a function immediately after the specified BasicBlock.
void
BasicBlock::insertAfter(BasicBlock *InsertPos)
{
    if (InsertPos->getParent() == nullptr)
    {
        return;
    }

    auto InsertPosIt = InsertPos->getParent()->getBasicBlockList().begin();
    for (; InsertPosIt != InsertPos->getParent()->getBasicBlockList().end(); ++InsertPosIt)
    {
        if (*InsertPosIt == InsertPos)
        {
            ++InsertPosIt;
            break;
        }
    }

    InsertPos->getParent()->getBasicBlockList().insert(InsertPosIt, this);
}

// Insert an unlinked instructions into a block
void
BasicBlock::insertInst(Instruction *I)
{
    push(I);
    I->setParent(this);
}

////////////////////////////////////////////////////////////
// Virtual functions
// Get the readable name of this object
std::string
BasicBlock::getReadableName() const
{
    // block.bbname
    std::string ReadableName = UIR_BLOCK_VARIABLE_NAME_PREFIX;
    ReadableName += mBasicBlockName;

    return ReadableName;
}

// Print the BasicBlock
void
BasicBlock::print(unknown::raw_ostream &OS) const
{
    // TODO
}

////////////////////////////////////////////////////////////
// Static
// Generate a new block name by order
std::string
BasicBlock::generateOrderedBasicBlockName(Context &C)
{
    auto CurIdx = C.mImpl->mOrderedBlockNameIndex++;
    return std::to_string(CurIdx);
}

// Creates a new BasicBlock.
BasicBlock *
BasicBlock::get(Context &C)
{
    return new BasicBlock(C);
}

// Creates a new BasicBlock.
BasicBlock *
BasicBlock::create(Context &C)
{
    return get(C);
}

// Creates a new BasicBlock.
BasicBlock *
BasicBlock::get(
    Context &C,
    unknown::StringRef BasicBlockName,
    uint64_t BasicBlockAddressBegin,
    uint64_t BasicBlockAddressEnd,
    Function *Parent)
{
    return new BasicBlock(C, BasicBlockName, BasicBlockAddressBegin, BasicBlockAddressEnd, Parent);
}

// Creates a new BasicBlock.
BasicBlock *
BasicBlock::create(
    Context &C,
    unknown::StringRef BasicBlockName,
    uint64_t BasicBlockAddressBegin,
    uint64_t BasicBlockAddressEnd,
    Function *Parent)
{
    return get(C, BasicBlockName, BasicBlockAddressBegin, BasicBlockAddressEnd, Parent);
}

} // namespace uir
