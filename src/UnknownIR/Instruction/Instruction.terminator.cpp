#include <Instruction.h>

namespace uir {
TerminatorInst::TerminatorInst(OpCodeID OpCodeId) : Instruction(OpCodeID::Unknown)
{
    //
}

TerminatorInst::~TerminatorInst()
{
    //
}

////////////////////////////////////////////////////////////
// Iterator
TerminatorInst::successor_iterator
TerminatorInst::successor_begin()
{
    return mSuccessorsList.begin();
}

TerminatorInst::const_successor_iterator
TerminatorInst::successor_begin() const
{
    return mSuccessorsList.cbegin();
}

TerminatorInst::successor_iterator
TerminatorInst::successor_end()
{
    return mSuccessorsList.end();
}

TerminatorInst::const_successor_iterator
TerminatorInst::successor_end() const
{
    return mSuccessorsList.cend();
}

BasicBlock *
TerminatorInst::successor_back()
{
    return mSuccessorsList.back();
}

BasicBlock *
TerminatorInst::successor_front()
{
    return mSuccessorsList.front();
}

void
TerminatorInst::successor_push(BasicBlock *BB)
{
    return mSuccessorsList.push_back(BB);
}

void
TerminatorInst::successor_pop()
{
    return mSuccessorsList.pop_back();
}

size_t
TerminatorInst::successor_count() const
{
    return mSuccessorsList.size();
}

void
TerminatorInst::successor_erase(BasicBlock *BB)
{
    for (auto It = mSuccessorsList.begin(); It != mSuccessorsList.end(); ++It)
    {
        if (*It == BB)
        {
            mSuccessorsList.erase(It);
            break;
        }
    }
}

bool
TerminatorInst::successor_empty() const
{
    return mSuccessorsList.empty();
}

} // namespace uir
