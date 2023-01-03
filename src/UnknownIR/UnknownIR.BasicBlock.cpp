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
    const unknown::StringRef &BasicBlockName,
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
    clearAllInstructions();
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
    for (auto It = predecessor_begin(); It != predecessor_end(); ++It)
    {
        if (*It == BB)
        {
            mPredecessorsList.erase(It);
            --It;
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
BasicBlock::setBasicBlockName(const unknown::StringRef &BlockName)
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
TerminatorInstruction *
BasicBlock::getTerminator()
{
    if (empty())
    {
        return nullptr;
    }

    auto Inst = *rbegin();
    if (Inst == nullptr)
    {
        return nullptr;
    }

    return dynamic_cast<TerminatorInstruction *>(Inst);
}

// Get the terminator instruction of this block
const TerminatorInstruction *
BasicBlock::getTerminator() const
{
    if (empty())
    {
        return nullptr;
    }

    auto Inst = *rbegin();
    if (Inst == nullptr)
    {
        return nullptr;
    }

    return dynamic_cast<const TerminatorInstruction *>(Inst);
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

    if (mParent->getBasicBlockList().empty())
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

    if (mParent->getBasicBlockList().empty())
    {
        return;
    }

    for (auto It = mParent->getBasicBlockList().begin(); It != mParent->getBasicBlockList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getBasicBlockList().erase(It);
            this->setParent(nullptr);
            --It;
        }
    }
}

// Insert an unlinked BasicBlock into a function immediately before/after the specified BasicBlock.
void
BasicBlock::insertBeforeOrAfter(BasicBlock *InsertPos, bool Before)
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
            if (!Before)
            {
                ++InsertPosIt;
            }

            break;
        }
    }

    InsertPos->getParent()->getBasicBlockList().insert(InsertPosIt, this);
    this->setParent(InsertPos->getParent());
}

// Insert an unlinked BasicBlock into a function immediately before the specified BasicBlock.
void
BasicBlock::insertBefore(BasicBlock *InsertPos)
{
    insertBeforeOrAfter(InsertPos, true);
}

// Insert an unlinked BasicBlock into a function immediately after the specified BasicBlock.
void
BasicBlock::insertAfter(BasicBlock *InsertPos)
{
    insertBeforeOrAfter(InsertPos, false);
}

// Insert an unlinked instructions into a block
void
BasicBlock::insertInst(Instruction *I)
{
    push(I);
    I->setParent(this);
}

// Drop all instructions in this block.
void
BasicBlock::dropAllReferences()
{
    if (empty())
    {
        return;
    }

    for (auto InstIt = begin(); InstIt != end(); ++InstIt)
    {
        auto Inst = *InstIt;
        if (Inst)
        {
            Inst->dropAllReferences();
        }
    }
}

// Clear all instructions in this block.
void
BasicBlock::clearAllInstructions()
{
    if (empty())
    {
        return;
    }

    // Drop all instructions in this block
    dropAllReferences();

    // Clear all operands
    for (auto InstIt = begin(); InstIt != end(); ++InstIt)
    {
        auto Inst = *InstIt;
        if (Inst)
        {
            Inst->clearAllOperands();
        }
    }

    // Free all instructions
    std::vector<Instruction *> FreeInstList;
    for (auto InstIt = begin(); InstIt != end(); ++InstIt)
    {
        auto Inst = *InstIt;
        if (Inst && Inst->user_empty())
        {
            if (std::find(FreeInstList.begin(), FreeInstList.end(), Inst) == FreeInstList.end())
            {
                FreeInstList.push_back(Inst);
                delete Inst;
            }
        }
    }

    // Clear instruction list
    clear();
}

////////////////////////////////////////////////////////////
// Virtual functions
// Get the readable name of this object
std::string
BasicBlock::getReadableName() const
{
    // block-bbname
    std::string ReadableName = UIR_BLOCK_VARIABLE_NAME_PREFIX;
    ReadableName += mBasicBlockName;

    return ReadableName;
}

// Get the property 'bb' of the value
unknown::StringRef
BasicBlock::getPropertyBB() const
{
    return "bb";
}

// Print the BasicBlock
void
BasicBlock::print(unknown::raw_ostream &OS, bool NewLine) const
{
    tinyxml2::XMLPrinter Printer;
    print(Printer);
    OS << Printer.CStr();
}

// Print the BasicBlock
void
BasicBlock::print(tinyxml2::XMLPrinter &Printer) const
{
    Printer.OpenElement(getPropertyBB().str().c_str());

    // name
    {
        Printer.PushAttribute(getPropertyName().str().c_str(), getReadableName().c_str());
    }

    // range
    {
        auto Range =
            std::format("0x{:X}", getBasicBlockAddressBegin()) + "-" + std::format("0x{:X}", getBasicBlockAddressEnd());
        Printer.PushAttribute(getPropertyRange().str().c_str(), Range.c_str());
    }

    // extra
    {
        std::string Extra("");
        unknown::raw_string_ostream OSExtra(Extra);
        printExtraInfo(OSExtra);
        if (!OSExtra.str().empty())
        {
            Printer.PushAttribute(getPropertyExtra().str().c_str(), OSExtra.str().c_str());
        }
    }

    // comment
    {
        std::string Comment("");
        unknown::raw_string_ostream OSComment(Comment);
        printCommentInfo(OSComment);
        if (!OSComment.str().empty())
        {
            Printer.PushAttribute(getPropertyComment().str().c_str(), OSComment.str().c_str());
        }
    }

    // inst
    for (auto Inst : *this)
    {
        if (Inst == nullptr)
        {
            continue;
        }

        Inst->print(Printer);
    }

    Printer.CloseElement();
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
    const unknown::StringRef &BasicBlockName,
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
    const unknown::StringRef &BasicBlockName,
    uint64_t BasicBlockAddressBegin,
    uint64_t BasicBlockAddressEnd,
    Function *Parent)
{
    return get(C, BasicBlockName, BasicBlockAddressBegin, BasicBlockAddressEnd, Parent);
}

} // namespace uir
