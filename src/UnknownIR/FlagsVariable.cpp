#include <FlagsVariable.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     FlagsVariable
//
FlagsVariable::FlagsVariable(Type *Ty) : LocalVariable(Ty, "flags", 0)
{
    mFlags.FlagsValue = 0;
}

FlagsVariable::FlagsVariable(Context &C) : FlagsVariable(Type::getInt64Ty(C))
{
    //
}

FlagsVariable::~FlagsVariable()
{
    //
}

////////////////////////////////////////////////////////////
// Get/Set
const FlagsVariable::Flags
FlagsVariable::getFlags() const
{
    return mFlags;
}

const uint64_t
FlagsVariable::getFlagsValue() const
{
    return mFlags.FlagsValue;
}

void
FlagsVariable::setFlags(Flags Flag)
{
    mFlags = Flag;
}

void
FlagsVariable::setFlagsValue(uint64_t FlagsVal)
{
    mFlags.FlagsValue = FlagsVal;
}

void
FlagsVariable::setCarryFlag(bool Set)
{
    mFlags.CarryFlag = Set ? 1 : 0;
}

void
FlagsVariable::setParityFlag(bool Set)
{
    mFlags.ParityFlag = Set ? 1 : 0;
}

void
FlagsVariable::setAuxParityFlag(bool Set)
{
    mFlags.AuxParityFlag = Set ? 1 : 0;
}

void
FlagsVariable::setZeroFlag(bool Set)
{
    mFlags.ZeroFlag = Set ? 1 : 0;
}

void
FlagsVariable::setSignFlag(bool Set)
{
    mFlags.SignFlag = Set ? 1 : 0;
}

void
FlagsVariable::setDirectionFlag(bool Set)
{
    mFlags.DirectionFlag = Set ? 1 : 0;
}

void
FlagsVariable::setOverflowFlag(bool Set)
{
    mFlags.OverflowFlag = Set ? 1 : 0;
}

////////////////////////////////////////////////////////////
// Static
FlagsVariable *
FlagsVariable::get(Type *Ty)
{
    return new FlagsVariable(Ty);
}

FlagsVariable *
FlagsVariable::get(Context &C)
{
    return new FlagsVariable(C);
}

} // namespace uir
