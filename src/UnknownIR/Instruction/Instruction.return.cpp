#include <Instruction.h>

#include <unknown/ADT/StringExtras.h>

namespace uir {
////////////////////////////////////////////////////////////
//     ReturnInst
//
ReturnInst::ReturnInst() : TerminatorInst(OpCodeID::Ret)
{
    //
}

ReturnInst::~ReturnInst()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
ReturnInst::getOpcodeName() const
{
    return RetComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
ReturnInst::getDefaultNumberOfOperands() const
{
    return RetComponent.mNumberOfOperands;
}

// Is this instruction with flags?
bool
ReturnInst::hasFlags() const
{
    return RetComponent.mHasFlags;
}

// Print the instruction
void
ReturnInst::print(unknown::raw_ostream &OS) const
{
    // address\tinst
    OS << "0x" << unknown::utohexstr(getInstructionAddress());
    OS << "\t";
    OS << getOpcodeName();
    OS << "\n";
}

////////////////////////////////////////////////////////////
// Static
ReturnInst *
ReturnInst::get()
{
    return new ReturnInst();
}

////////////////////////////////////////////////////////////
//     ReturnImmInst
//
ReturnImmInst::ReturnImmInst(ConstantInt *ImmConstantInt) : TerminatorInst(OpCodeID::RetIMM)
{
    // Insert ImmConstantInt   -> op1
    insertOperandAndUpdateUsers(ImmConstantInt);
}

ReturnImmInst::~ReturnImmInst()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
ReturnImmInst::getOpcodeName() const
{
    return RetIMMComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
ReturnImmInst::getDefaultNumberOfOperands() const
{
    return RetIMMComponent.mNumberOfOperands;
}

// Is this instruction with flags?
bool
ReturnImmInst::hasFlags() const
{
    return RetIMMComponent.mHasFlags;
}

// Print the instruction
void
ReturnImmInst::print(unknown::raw_ostream &OS) const
{
    // address\tinst
    OS << "0x" << unknown::utohexstr(getInstructionAddress());
    OS << "\t";
    OS << getOpcodeName();
    OS << " ";
    OS << getImmConstantInt()->getReadableName();
    OS << "\n";
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the immediate constant int
const ConstantInt *
ReturnImmInst::getImmConstantInt() const
{
    return dynamic_cast<const ConstantInt *>(getOperand(0));
}

// Set the immediate constant int
void
ReturnImmInst::setImmConstantInt(ConstantInt *ImmConstantInt)
{
    setOperandAndUpdateUsers(0, ImmConstantInt);
}

////////////////////////////////////////////////////////////
// Static
ReturnImmInst *
ReturnImmInst::get(ConstantInt *ImmConstantInt)
{
    return new ReturnImmInst(ImmConstantInt);
}

} // namespace uir
