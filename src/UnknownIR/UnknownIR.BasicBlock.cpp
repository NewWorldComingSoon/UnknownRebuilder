#include <BasicBlock.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     BasicBlock
//
BasicBlock::BasicBlock(
    Context &C,
    const char *BasicBlockName,
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
// Get the readable name of this object
std::string
BasicBlock::getReadableName() const
{
    // block:bbname
    std::string ReadableName = UIR_BLOCK_VARIABLE_NAME_PREFIX;
    ReadableName += mBasicBlockName;

    return ReadableName;
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

} // namespace uir
