#include <Instruction.h>
#include <BasicBlock.h>
#include <GlobalVariable.h>
#include <LocalVariable.h>
#include <Function.h>
#include <Argument.h>
#include <FunctionContext.h>

#include <Internal/InternalErrors/InternalErrors.h>
#include <Internal/InternalConfig/InternalConfig.h>

#include <unknown/ADT/StringExtras.h>

namespace uir {
////////////////////////////////////////////////////////////
//     Instruction
//
Instruction::Instruction(Context &C) : Instruction(C, OpCodeID::Unknown)
{
    //
}

Instruction::Instruction(Context &C, OpCodeID OpCodeId) : Instruction(OpCodeId, Type::getVoidTy(C))
{
    //
}

Instruction::Instruction(OpCodeID OpCodeId, Type *Ty) :
    LocalVariable(Ty),
    mOpCodeID(OpCodeId),
    mInstructionAddress(0),
    mParent(nullptr),
    mFlagsVariable(nullptr),
    mStackVariable(nullptr),
    mEnablePrintOp(false)
{
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

// Is this instruction with result?
bool
Instruction::hasResult() const
{
    return UnknownComponent.mHasResult;
}

// Is this instruction with flags?
bool
Instruction::hasFlags() const
{
    return UnknownComponent.mHasFlags;
}

// Get the property 'inst' of the value
unknown::StringRef
Instruction::getPropertyInst() const
{
    return "i";
}

// Get the property 'op' of the value
unknown::StringRef
Instruction::getPropertyOp() const
{
    return "op";
}

// Get the property 'res' of the value
unknown::StringRef
Instruction::getPropertyOpRes() const
{
    return "res";
}

// Get the property 'opcode' of the value
unknown::StringRef
Instruction::getPropertyOpCode() const
{
    return "opcode";
}

// Print the full instruction
void
Instruction::print(unknown::raw_ostream &OS, bool NewLine) const
{
    unknown::XMLPrinter Printer;
    print(Printer);
    OS << Printer.CStr();
}

// Print the full instruction
void
Instruction::print(unknown::XMLPrinter &Printer) const
{
    Printer.OpenElement(getPropertyInst().data());

    // addr
    {
        Printer.PushAttribute(getPropertyAddr().data(), std::format("0x{:X}", getInstructionAddress()).c_str());
    }

    // name
    {
        std::string Name("");
        unknown::raw_string_ostream OSName(Name);
        printInst(OSName);
        Printer.PushAttribute(getPropertyName().data(), OSName.str().c_str());
    }

    // extra
    {
        std::string Extra("");
        unknown::raw_string_ostream OSExtra(Extra);
        printExtraInfo(OSExtra);
        if (!OSExtra.str().empty())
        {
            Printer.PushAttribute(getPropertyExtra().data(), OSExtra.str().c_str());
        }
    }

    // comment
    {
        std::string Comment("");
        unknown::raw_string_ostream OSComment(Comment);
        printCommentInfo(OSComment);
        if (!OSComment.str().empty())
        {
            Printer.PushAttribute(getPropertyComment().data(), OSComment.str().c_str());
        }
    }

    // op
    if (hasPrintOp())
    {
        printOp(Printer);
    }

    Printer.CloseElement();
}

// Print the instruction
void
Instruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
}

// Print the operand
void
Instruction::printOp(unknown::XMLPrinter &Printer) const
{
    Printer.OpenElement(getPropertyOpCode().data());
    Printer.PushAttribute(getPropertyName().data(), getOpcodeName().data());
    Printer.CloseElement();

    for (uint32_t i = 0; i < getDefaultNumberOfOperands(); ++i)
    {
        Printer.OpenElement(getPropertyOp().data());
        Printer.PushAttribute(getPropertyName().data(), getOperand(i)->getReadableName().c_str());
        Printer.CloseElement();
    }

    if (hasResult())
    {
        Printer.OpenElement(getPropertyOpRes().data());
        Printer.PushAttribute(getPropertyName().data(), getReadableName().c_str());
        Printer.CloseElement();
    }
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
    return mFlagsVariable.get();
}

// Get the flags variable of this instruction
FlagsVariable *
Instruction::getFlagsVariable()
{
    return mFlagsVariable.get();
}

// Set the flags variable of this instruction
void
Instruction::setFlagsVariable(std::unique_ptr<FlagsVariable> &&FV)
{
    mFlagsVariable = std::move(FV);
}

// Set the flags variable of this instruction
void
Instruction::setFlagsVariable(FlagsVariable *FV)
{
    setFlagsVariable(std::unique_ptr<FlagsVariable>(FV));
}

// Set the flags variable of this instruction and update its users
void
Instruction::setFlagsVariableAndUpdateUsers(FlagsVariable *FV)
{
    if (mFlagsVariable.get() == FV)
    {
        return;
    }

    auto OldFlagsVariable = mFlagsVariable.get();

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
    return mStackVariable.get();
}

// Get the stack variable of this instruction
LocalVariable *
Instruction::getStackVariable()
{
    return mStackVariable.get();
}

// Set the stack variable of this instruction
void
Instruction::setStackVariable(std::unique_ptr<LocalVariable> &&SV)
{
    mStackVariable = std::move(SV);
}

// Set the stack variable of this instruction
void
Instruction::setStackVariable(LocalVariable *SV)
{
    setStackVariable(std::unique_ptr<LocalVariable>(SV));
}

// Set the stack variable of this instruction and update its users
void
Instruction::setStackVariableAndUpdateUsers(LocalVariable *SV)
{
    if (mStackVariable.get() == SV)
    {
        return;
    }

    auto OldStackVariable = mStackVariable.get();

    // Set the new variable
    setStackVariable(SV);

    // Update its users
    if (OldStackVariable)
    {
        OldStackVariable->user_erase(this);
    }

    if (SV)
    {
        SV->user_insert(this);
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

    if (mParent->getInstList().empty())
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

    if (mParent->getInstList().empty())
    {
        return;
    }

    for (auto It = mParent->getInstList().begin(); It != mParent->getInstList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getInstList().erase(It);
            this->setParent(nullptr);
            --It;
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

    auto InsertPosIt = InsertPos->getParent()->getInstList().begin();
    for (; InsertPosIt != InsertPos->getParent()->getInstList().end(); ++InsertPosIt)
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

    InsertPos->getParent()->getInstList().insert(InsertPosIt, this);
    this->setParent(InsertPos->getParent());
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

// Drop all references to operands.
void
Instruction::dropAllReferences()
{
    User::dropAllReferences();

    // Unlink flags variable from its user list
    if (mFlagsVariable)
    {
        mFlagsVariable->user_erase(this);
        mFlagsVariable = nullptr;
    }

    // Unlink stack variable from its user list
    if (mStackVariable)
    {
        mStackVariable->user_erase(this);
        mStackVariable = nullptr;
    }
}

// Clear all operands in this instruction.
void
Instruction::clearAllOperands()
{
    // Drop all references to operands
    dropAllReferences();

    // Free all operands
    std::vector<Value *> FreeOperandsList;
    for (auto OPIt = op_begin(); OPIt != op_end(); ++OPIt)
    {
        auto OP = *OPIt;
        if (OP == nullptr)
        {
            continue;
        }

        if (!OP->user_empty())
        {
            continue;
        }

        if (auto CI = dynamic_cast<ConstantInt *>(OP))
        {
            // We do not free constant integer
            continue;
        }

        if (auto GV = dynamic_cast<GlobalVariable *>(OP))
        {
            // We do not free global variable
            continue;
        }

        if (auto BB = dynamic_cast<BasicBlock *>(OP))
        {
            // We do not free block
            continue;
        }

        if (auto Arg = dynamic_cast<Argument *>(OP))
        {
            // We do not free argument
            continue;
        }

        if (auto FC = dynamic_cast<FunctionContext *>(OP))
        {
            // We do not free function context
            continue;
        }

        if (std::find(FreeOperandsList.begin(), FreeOperandsList.end(), OP) == FreeOperandsList.end())
        {
            FreeOperandsList.push_back(OP);
            delete OP;
        }
    }

    // Clear operand list
    op_clear();
}

// Enabled
// Enable 'print detailed op'
void
Instruction::enablePrintOp(bool Enable)
{
    mEnablePrintOp = Enable;
}

// Is this instruction Enable 'print detailed op'?
bool
Instruction::hasPrintOp() const
{
    return mEnablePrintOp;
}

////////////////////////////////////////////////////////////
//     TerminatorInstruction
//
TerminatorInstruction::TerminatorInstruction(Context &C, OpCodeID OpCodeId) : Instruction(C, OpCodeId)
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
            --It;
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