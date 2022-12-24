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
