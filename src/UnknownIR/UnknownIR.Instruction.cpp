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
    mExtraInfo = "";
    mComment = "";

    if (mFlagsVariable)
    {
        mFlagsVariable->user_insert(this);
    }

    if (mStackVariable)
    {
        mStackVariable->user_insert(this);
    }
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
    OS << "0x" << unknown::APInt(64, getInstructionAddress()).toString(16, false);
    OS << "\t";
    OS << getOpcodeName();
    OS << "\n";
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

    if (FV)
    {
        FV->user_insert(this);
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

// Get the extra info of this instruction
const std::string
Instruction::getExtraInfo() const
{
    return mExtraInfo;
}

// Set the extra info of this instruction
void
Instruction::setExtraInfo(unknown::StringRef ExtraInfo)
{
    mExtraInfo = ExtraInfo;
}

// Append the extra info of this instruction
void
Instruction::appendExtraInfo(unknown::StringRef ExtraInfo)
{
    mExtraInfo += ExtraInfo;
}

// Get the comment of this instruction
const std::string
Instruction::getComment() const
{
    return mComment;
}

// Set the comment of this instruction
void
Instruction::setComment(unknown::StringRef Comment)
{
    mComment = Comment;
}

// Append the comment of this instruction
void
Instruction::appendComment(unknown::StringRef Comment)
{
    mComment += Comment;
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

// Insert an unlinked instructions into a basic block immediately before/after the specified instruction.
void
Instruction::insertBeforeOrAfter(Instruction *InsertPos, bool Before)
{
    if (InsertPos->getParent() == nullptr)
    {
        return;
    }

    bool CanInsert = true;
    auto InsertPosIt = InsertPos->getParent()->getInstList().begin();
    for (; InsertPosIt != InsertPos->getParent()->getInstList().end(); ++InsertPosIt)
    {
        if (*InsertPosIt == this)
        {
            CanInsert = false;
            break;
        }

        if (*InsertPosIt == InsertPos)
        {
            if (!Before)
            {
                ++InsertPosIt;
            }

            break;
        }
    }

    if (CanInsert)
    {
        InsertPos->getParent()->getInstList().insert(InsertPosIt, this);
    }
}

// Insert an unlinked instructions into a basic block immediately before the specified instruction.
void
Instruction::insertBefore(Instruction *InsertPos)
{
    insertBeforeOrAfter(InsertPos, true);
}

// Insert an unlinked instructions into a basic block immediately after the specified instruction.
void
Instruction::insertAfter(Instruction *InsertPos)
{
    insertBeforeOrAfter(InsertPos, false);
}

// Clear all operands in this instruction.
void
Instruction::clearAllOperands()
{
    // TODO
}

////////////////////////////////////////////////////////////
// Static
Instruction *
Instruction::get(OpCodeID OpCodeId)
{
    return new Instruction(OpCodeId);
}

////////////////////////////////////////////////////////////
//     TerminatorInstruction
//
TerminatorInstruction::TerminatorInstruction(OpCodeID OpCodeId) : Instruction(OpCodeID::Unknown)
{
    //
}

TerminatorInstruction::~TerminatorInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Iterator
TerminatorInstruction::successor_iterator
TerminatorInstruction::successor_begin()
{
    return mSuccessorsList.begin();
}

TerminatorInstruction::const_successor_iterator
TerminatorInstruction::successor_begin() const
{
    return mSuccessorsList.cbegin();
}

TerminatorInstruction::successor_iterator
TerminatorInstruction::successor_end()
{
    return mSuccessorsList.end();
}

TerminatorInstruction::const_successor_iterator
TerminatorInstruction::successor_end() const
{
    return mSuccessorsList.cend();
}

BasicBlock *
TerminatorInstruction::successor_back()
{
    return mSuccessorsList.back();
}

BasicBlock *
TerminatorInstruction::successor_front()
{
    return mSuccessorsList.front();
}

void
TerminatorInstruction::successor_push(BasicBlock *BB)
{
    return mSuccessorsList.push_back(BB);
}

void
TerminatorInstruction::successor_pop()
{
    return mSuccessorsList.pop_back();
}

size_t
TerminatorInstruction::successor_count() const
{
    return mSuccessorsList.size();
}

void
TerminatorInstruction::successor_erase(BasicBlock *BB)
{
    for (auto It = successor_begin(); It != successor_end(); ++It)
    {
        if (*It == BB)
        {
            mSuccessorsList.erase(It);
            break;
        }
    }
}

bool
TerminatorInstruction::successor_empty() const
{
    return mSuccessorsList.empty();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the number of successors that this terminator has.
size_t
TerminatorInstruction::getNumSuccessors() const
{
    return successor_count();
}

// Get the specified successor.
BasicBlock *
TerminatorInstruction::getSuccessor(size_t Index) const
{
    assert(Index < mSuccessorsList.size() && "getSuccessor() out of range!");
    if (!successor_empty())
    {
        return mSuccessorsList[Index];
    }

    return nullptr;
}

// Set the specified successor to point at the provided block.
void
TerminatorInstruction::setSuccessor(size_t Index, BasicBlock *Successor)
{
    assert(Index < mSuccessorsList.size() && "setSuccessor() out of range!");
    assert(Successor != nullptr && "setSuccessor() Successor == nullptr!");
    mSuccessorsList[Index] = Successor;
}

// Set the specified successor to point at the provided block and update its predecessor.
void
TerminatorInstruction::setSuccessorAndUpdatePredecessor(size_t Index, BasicBlock *Successor)
{
    assert(Index < mSuccessorsList.size() && "setSuccessorAndUpdatePredecessor() out of range!");
    assert(Successor != nullptr && "setSuccessorAndUpdatePredecessor() Successor == nullptr!");

    auto OldSuccessor = mSuccessorsList[Index];
    if (OldSuccessor == Successor)
    {
        return;
    }
    assert(OldSuccessor != nullptr && "setSuccessorAndUpdatePredecessor() OldSuccessor == nullptr!");

    // Set the new successor.
    setSuccessor(Index, Successor);

    // Erase the predecessor list of the old successor.
    OldSuccessor->predecessor_erase(this->getParent());

    // Update the predecessor list of the new successor.
    Successor->predecessor_push(this->getParent());
}

// Insert a new successor into the terminator instruction.
void
TerminatorInstruction::insertSuccessor(BasicBlock *BB)
{
    if (std::find(successor_begin(), successor_end(), BB) == successor_end())
    {
        successor_push(BB);
    }
}

// Erase a successor into the terminator instruction.
void
TerminatorInstruction::eraseSuccessor(BasicBlock *BB)
{
    successor_erase(BB);
}

} // namespace uir