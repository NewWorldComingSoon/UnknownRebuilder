#include <Instruction.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

UnknownInstruction::UnknownInstruction(unknown::StringRef UnknownStr) :
    Instruction(OpCodeID::Unknown), mUnknownStr(UnknownStr)
{
    //
}

UnknownInstruction ::~UnknownInstruction()
{
    //
}

////////////////////////////////////////////////////////////
// Virtual
// Get the opcode name of this instruction
unknown::StringRef
UnknownInstruction::getOpcodeName() const
{
    return UnknownComponent.mOpCodeName;
}

// Get the default number of operands
uint32_t
UnknownInstruction::getDefaultNumberOfOperands() const
{
    return UnknownComponent.mNumberOfOperands;
}

// Is this instruction with result?
bool
UnknownInstruction::hasResult() const
{
    return UnknownComponent.mHasResult;
}

// Is this instruction with flags?
bool
UnknownInstruction::hasFlags() const
{
    return UnknownComponent.mHasFlags;
}

// Print the instruction
void
UnknownInstruction::printInst(unknown::raw_ostream &OS) const
{
    OS << getOpcodeName();
    OS << UIR_OPCODE_SEPARATOR;
    OS << R"(")";
    OS << getUnknownStr();
    OS << R"(")";
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the unknown string
std::string
UnknownInstruction::getUnknownStr() const
{
    return mUnknownStr;
}

////////////////////////////////////////////////////////////
// Static
UnknownInstruction *
UnknownInstruction::get(unknown::StringRef UnknownStr)
{
    return new UnknownInstruction(UnknownStr);
}

} // namespace uir
