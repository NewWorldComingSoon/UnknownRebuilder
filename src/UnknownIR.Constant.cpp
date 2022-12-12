#include <Constant.h>
#include <User.h>

#include <sstream>
#include <string>
#include <cassert>

#include <Internal/InternalErrors/InternalErrors.h>
#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {
////////////////////////////////////////////////////////////
//     Constant
//
Constant::Constant(Type *Ty, const std::string ConstantName) : Value(Ty, ConstantName)
{
    //
    //
}

Constant::~Constant()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the "To"
void
Constant::replaceUsesOfWith(Value *From, Value *To)
{
    // nothing
}

// Change all uses of this to point to a new Value.
void
Constant::replaceAllUsesWith(Value *V)
{
    if (V == this)
    {
        // We will not replace ourself.
        return;
    }

    // Replace all uses of this value with the new value.
    for (auto &User : mUsers)
    {
        User->replaceUsesOfWith(this, V);
    }
}

////////////////////////////////////////////////////////////
//     ConstantInt
//
ConstantInt::ConstantInt(Type *Ty, uint64_t Val) : Constant(Ty, std::to_string(setValue(Val, Ty->getTypeBits(), true)))
{
    //
    //
}

ConstantInt::~ConstantInt()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Replace
// Replaces all references to the "From" definition with references to the "To"
void
ConstantInt::replaceUsesOfWith(Value *From, Value *To)
{
    // nothing
}

// Change all uses of this to point to a new Value.
void
ConstantInt::replaceAllUsesWith(Value *V)
{
    // nothing
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the readable name of this object
std::string
ConstantInt::getReadableName() const
{
    // 1234 i32
    std::string ReadableName = getName();
    ReadableName += " ";
    ReadableName += mType->getTypeName();

    return ReadableName;
}

// Get/Set the value of ConstantInt
uint64_t
ConstantInt::getValue() const
{
    return mVal;
}

uint64_t
ConstantInt::getZExtValue() const
{
    assert(getBitWidth() > 64 && "Too many bits for uint64_t");
    return mVal;
}

int64_t
ConstantInt::getSExtValue() const
{
    assert(getBitWidth() > 64 && "Too many bits for int64_t");
    return (int64_t)mVal;
}

void
ConstantInt::setValue(uint64_t Val)
{
    setValue(Val, mType->getTypeBits(), false);
}

uint64_t
ConstantInt::setValue(uint64_t Val, uint32_t BitWidth, bool RetNewVal)
{
    uint64_t OldVal = mVal;

    mVal = convertValue(Val, BitWidth);

    if (RetNewVal)
    {
        return mVal;
    }
    else
    {
        return OldVal;
    }
}

// Return the bitwidth of this constant.
uint32_t
ConstantInt::getBitWidth() const
{
    return getValueBits();
}

////////////////////////////////////////////////////////////
// Static

uint64_t
ConstantInt::convertValue(uint64_t Val, uint32_t BitWidth)
{
    uint64_t NewVal = 0;
    if (BitWidth == 1)
    {
        if (Val)
        {
            NewVal = 1;
        }
        else
        {
            NewVal = 0;
        }
    }
    else if (BitWidth == 8)
    {
        NewVal = (uint64_t)((uint8_t)Val);
    }
    else if (BitWidth == 16)
    {
        NewVal = (uint64_t)((uint16_t)Val);
    }
    else if (BitWidth == 32)
    {
        NewVal = (uint64_t)((uint32_t)Val);
    }
    else if (BitWidth == 64)
    {
        NewVal = (uint64_t)((uint64_t)Val);
    }
    else
    {
        uir_unreachable("Unknown BitWidth in ConstantInt::convertValue");
    }

    return NewVal;
}

std::string
ConstantInt::toHexString(uint64_t Val, uint32_t BitWidth)
{
    return "";
}

std::string
ConstantInt::toDecimalString(uint64_t Val, uint32_t BitWidth)
{
    return "";
}

} // namespace uir