#include <Instruction.h>
#include <BasicBlock.h>

namespace uir {

Instruction::Instruction() : Instruction(OpCodeID::Unknown)
{
    //
    //
}

Instruction::Instruction(OpCodeID OpCodeId) : mOpCodeID(OpCodeId), mInstructionAddress(0), mParent(nullptr)
{
    //
    //
}

Instruction::~Instruction()
{
    //
    //
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

////////////////////////////////////////////////////////////
// Print
// Print the instruction
void
Instruction::print(unknown::raw_ostream &OS) const
{
    // TODO
}

} // namespace uir