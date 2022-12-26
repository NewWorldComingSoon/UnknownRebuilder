#include <Constant.h>
#include <User.h>
#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalErrors/InternalErrors.h>
#include <Internal/InternalConfig/InternalConfig.h>

#include <unknown/ADT/StringExtras.h>

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
// Static
// Get a Constant object
Constant *
Constant::get(Type *Ty, unknown::StringRef ConstantName)
{
    return new Constant(Ty, ConstantName);
}

////////////////////////////////////////////////////////////
//     ConstantInt
//
ConstantInt::ConstantInt(Type *Ty, const unknown::APInt &Val) : Constant(Ty, "0x" + Val.toString(16, false)), mVal(Val)
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
const unknown::APInt &
ConstantInt::getValue() const
{
    return mVal;
}

uint64_t
ConstantInt::getZExtValue() const
{
    return mVal.getZExtValue();
}

int64_t
ConstantInt::getSExtValue() const
{
    return mVal.getSExtValue();
}

void
ConstantInt::setValue(const unknown::APInt &Val)
{
    mVal = Val;
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
// Get a ConstantInt from a value
ConstantInt *
ConstantInt::get(Context &Context, const unknown::APInt &Val)
{
    ContextImpl *Impl = Context.mImpl;
    ConstantInt *Slot = Impl->mIntConstants[Val];
    if (Slot == nullptr)
    {
        // Get the corresponding integer type for the bit width of the value.
        IntegerType *IntTy = IntegerType::get(Context, Val.getBitWidth());
        Slot = new ConstantInt(IntTy, Val);
    }
    assert(Slot->getType() == IntegerType::get(Context, Val.getBitWidth()));
    return Slot;
}

// Get a ConstantInt from a value
ConstantInt *
ConstantInt::get(IntegerType *Ty, const unknown::APInt &Val)
{
    return get(Ty->getContext(), Val);
}

} // namespace uir
