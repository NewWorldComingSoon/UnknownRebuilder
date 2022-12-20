#include <Instruction.h>

namespace uir {

Instruction::Instruction() : Instruction(uir::OpCodeID::Unknown)
{
    //
    //
}

Instruction::Instruction(uir::OpCodeID OpCodeId) : mOpCodeID(OpCodeId), mInstructionAddress(0)
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

////////////////////////////////////////////////////////////
// Print
// Print the instruction
void
Instruction::print(unknown::raw_ostream &OS) const
{
    // TODO
}

} // namespace uir