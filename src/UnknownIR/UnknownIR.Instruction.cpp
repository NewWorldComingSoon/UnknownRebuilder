#include <Instruction.h>
#include <BasicBlock.h>

#include <Internal/InternalErrors/InternalErrors.h>

#include <unknown/ADT/StringExtras.h>

namespace uir {
////////////////////////////////////////////////////////////
//     Instruction
//
Instruction::Instruction() : Instruction(OpCodeID::Unknown)
{
    //
    //
}

Instruction::Instruction(OpCodeID OpCodeId) :
    mOpCodeID(OpCodeId), mInstructionAddress(0), mParent(nullptr), mFlagsVariable(nullptr), mStackVariable(nullptr)
{
    //
    //
}

Instruction::~Instruction()
{
    if (mFlagsVariable)
    {
        mFlagsVariable->user_erase(this);
    }

    if (mStackVariable)
    {
        mStackVariable->user_erase(this);
    }
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
Instruction::getOpcodeName() const
{
    return UnknownComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
Instruction::getDefaultNumberOfOperands() const
{
    return UnknownComponent.mNumberOfOperands;
}

// Is this instruction with flags?
bool
Instruction::hasFlags() const
{
    return UnknownComponent.mHasFlags;
}

// Print the instruction
void
Instruction::print(unknown::raw_ostream &OS) const
{
    // address\tinst
    OS << "0x" << unknown::utohexstr(getInstructionAddress());
    OS << "\t";
    OS << getOpcodeName();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the address of this instruction
uint64_t
Instruction::getInstructionAddress() const
{
    return mInstructionAddress;
}

// Set the address of this instruction
void
Instruction::setInstructionAddress(uint64_t InstructionAddress)
{
    mInstructionAddress = InstructionAddress;
}

// Get the parent of this instruction
const BasicBlock *
Instruction::getParent() const
{
    return mParent;
}

// Get the parent of this instruction
BasicBlock *
Instruction::getParent()
{
    return mParent;
}

// Set the parent of this instruction
void
Instruction::setParent(BasicBlock *BB)
{
    mParent = BB;
}

// Get the opcode of this instruction
const OpCodeID
Instruction::getOpCodeID() const
{
    return mOpCodeID;
}

// Set the opcode of this instruction
void
Instruction::setOpCodeID(OpCodeID OpCodeId)
{
    mOpCodeID = OpCodeId;
}

// Get the flags variable of this instruction
const FlagsVariable *
Instruction::getFlagsVariable() const
{
    return mFlagsVariable;
}

// Get the flags variable of this instruction
FlagsVariable *
Instruction::getFlagsVariable()
{
    return mFlagsVariable;
}

// Set the flags variable of this instruction
void
Instruction::setFlagsVariable(FlagsVariable *FV)
{
    mFlagsVariable = FV;
}

// Set the flags variable of this instruction and update its users
void
Instruction::setFlagsVariableAndUpdateUsers(FlagsVariable *FV)
{
    if (mFlagsVariable == FV)
    {
        return;
    }

    auto OldFlagsVariable = mFlagsVariable;

    // Set the new flags variable
    setFlagsVariable(FV);

    // Update its users
    if (OldFlagsVariable)
    {
        OldFlagsVariable->user_erase(this);
    }
    else
    {
        uir_unreachable("OldFlagsVariable == nullptr in Instruction::setFlagsVariableAndUpdateUsers");
    }

    if (FV)
    {
        FV->user_insert(this);
    }
    else
    {
        uir_unreachable("FV == nullptr in Instruction::setFlagsVariableAndUpdateUsers");
    }
}

// Get the stack variable of this instruction
const LocalVariable *
Instruction::getStackVariable() const
{
    return mStackVariable;
}

// Get the stack variable of this instruction
LocalVariable *
Instruction::getStackVariable()
{
    return mStackVariable;
}

// Set the stack variable of this instruction
void
Instruction::setStackVariable(LocalVariable *SV)
{
    mStackVariable = SV;
}

// Set the stack variable of this instruction and update its users
void
Instruction::setStackVariableAndUpdateUsers(LocalVariable *SV)
{
    if (mStackVariable == SV)
    {
        return;
    }

    auto OldStackVariable = mStackVariable;

    // Set the new variable
    setStackVariable(SV);

    // Update its users
    if (OldStackVariable)
    {
        OldStackVariable->user_erase(this);
    }
    else
    {
        uir_unreachable("OldStackVariable == nullptr in Instruction::setStackVariableAndUpdateUsers");
    }

    if (SV)
    {
        SV->user_insert(this);
    }
    else
    {
        uir_unreachable("SV == nullptr in Instruction::setStackVariableAndUpdateUsers");
    }
}

////////////////////////////////////////////////////////////
// Remove/Erase/Insert
// Remove this instruction from its parent, but does not delete it.
void
Instruction::removeFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    mParent->getInstList().remove(this);
}

// Remove this instruction from its parent and delete it.
void
Instruction::eraseFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    for (auto It = mParent->getInstList().begin(); It != mParent->getInstList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getInstList().erase(It);
            break;
        }
    }
}

// Insert an unlinked instructions into a basic block immediately before the specified instruction.
void
Instruction::insertBefore(Instruction *InsertPos)
{
    if (InsertPos->getParent() == nullptr)
    {
        return;
    }

    auto InsertPosIt = InsertPos->getParent()->getInstList().begin();
    for (; InsertPosIt != InsertPos->getParent()->getInstList().end(); ++InsertPosIt)
    {
        if (*InsertPosIt == InsertPos)
        {
            break;
        }
    }

    InsertPos->getParent()->getInstList().insert(InsertPosIt, this);
}

// Insert an unlinked instructions into a basic block immediately after the specified instruction.
void
Instruction::insertAfter(Instruction *InsertPos)
{
    if (InsertPos->getParent() == nullptr)
    {
        return;
    }

    auto InsertPosIt = InsertPos->getParent()->getInstList().begin();
    for (; InsertPosIt != InsertPos->getParent()->getInstList().end(); ++InsertPosIt)
    {
        if (*InsertPosIt == InsertPos)
        {
            ++InsertPosIt;
            break;
        }
    }

    InsertPos->getParent()->getInstList().insert(InsertPosIt, this);
}

////////////////////////////////////////////////////////////
// Static
Instruction *
Instruction::get(OpCodeID OpCodeId)
{
    return new Instruction(OpCodeId);
}

////////////////////////////////////////////////////////////
//     TerminatorInst
//
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

////////////////////////////////////////////////////////////
// Get/Set
// Get the number of successors that this terminator has.
size_t
TerminatorInst::getNumSuccessors() const
{
    return successor_count();
}

// Get the specified successor.
BasicBlock *
TerminatorInst::getSuccessor(size_t Index) const
{
    assert(Index < mSuccessorsList.size() && "getSuccessor() out of range!");
    if (!mSuccessorsList.empty())
    {
        return mSuccessorsList[Index];
    }

    return nullptr;
}

// Set the specified successor to point at the provided block.
void
TerminatorInst::setSuccessor(size_t Index, BasicBlock *BB)
{
    assert(Index < mSuccessorsList.size() && "setSuccessor() out of range!");
    mSuccessorsList[Index] = BB;
}

} // namespace uir