#include <Constant.h>

namespace uir {
////////////////////////////////////////////////////////////
//     Constant
//
Constant::Constant()
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
ConstantInt::ConstantInt()
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

void
ConstantInt::setValue(uint64_t Val)
{
    mVal = Val;
}

} // namespace uir
