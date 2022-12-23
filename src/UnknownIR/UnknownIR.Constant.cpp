

#include <sstream>
#include <string>
#include <cassert>

#include <Constant.h>
#include <User.h>
#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalErrors/InternalErrors.h>
#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {
////////////////////////////////////////////////////////////
//     Constant
//
Constant::Constant(Type *Ty, unknown::StringRef ConstantName) : User(Ty, ConstantName)
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
//     ConstantInt
//
ConstantInt::ConstantInt(Type *Ty, uint64_t Val) :
    Constant(Ty, toHexString(setValue(Val, Ty->getTypeBits(), true), Ty->getTypeBits()).c_str())
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
// Get/Set
// Get/Set the value of ConstantInt
uint64_t
ConstantInt::getValue() const
{
    return mVal;
}

uint64_t
ConstantInt::getZExtValue() const
{
    assert(getBitWidth() <= 64 && "Too many bits for uint64_t");
    return mVal;
}

int64_t
ConstantInt::getSExtValue() const
{
    assert(getBitWidth() <= 64 && "Too many bits for int64_t");
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
// Virtual functions
// Get the readable name of this object
std::string
ConstantInt::getReadableName() const
{
    // 0x7b i32
    std::string ReadableName = getName();
    ReadableName += " ";
    ReadableName += mType->getTypeName();

    return ReadableName;
}

////////////////////////////////////////////////////////////
// Static
// Using BitWidth to convert a value to a new value
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

// Using BitWidth to convert a value to a new hex string
std::string
ConstantInt::toHexString(uint64_t Val, uint32_t BitWidth)
{
    uint64_t NewVal = convertValue(Val, BitWidth);
    std::stringstream SS;
    SS << "0x";
    SS << std::hex << NewVal;
    return SS.str();
}

// Using BitWidth to convert a value to a new decimal string
std::string
ConstantInt::toDecimalString(uint64_t Val, uint32_t BitWidth)
{
    uint64_t NewVal = convertValue(Val, BitWidth);
    std::stringstream SS;
    SS << NewVal;
    return SS.str();
}

// Get a ConstantInt from a value
ConstantInt *
ConstantInt::get(Context &Context, uint64_t Val, uint32_t BitWidth)
{
    uint64_t NewVal = convertValue(Val, BitWidth);
    ContextImpl *Impl = Context.mImpl;
    ConstantInt *Slot = Impl->mIntConstants[NewVal];
    if (Slot == nullptr)
    {
        // Get the corresponding integer type for the bit width of the value.
        IntegerType *IntTy = IntegerType::get(Context, BitWidth);
        Slot = new ConstantInt(IntTy, NewVal);
    }
    assert(Slot->getType() == IntegerType::get(Context, BitWidth));
    return Slot;
}

// Get a ConstantInt from a value
ConstantInt *
ConstantInt::get(IntegerType *Ty, uint64_t Val, uint32_t BitWidth)
{
    return get(Ty->getContext(), Val, BitWidth);
}

} // namespace uir
