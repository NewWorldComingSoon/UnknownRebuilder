#include <FunctionContext.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     FunctionContext
//
FunctionContext::FunctionContext(Type *Ty, const unknown::StringRef &CtxName, Function *F, uint32_t CtxNo) :
    Constant(Ty, CtxName), mParent(F), mCtxNo(CtxNo)
{
    //
    //
}

FunctionContext::~FunctionContext()
{
    //
    //
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the parent function of this argument
const Function *
FunctionContext::getParent() const
{
    return mParent;
}

Function *
FunctionContext::getParent()
{
    return mParent;
}

// Set the parent function of this argument
void
FunctionContext::setParent(Function *F)
{
    mParent = F;
}

// Get the context number of this argument
const uint32_t
FunctionContext::getCtxNo() const
{
    assert(mParent && "can't get number of unparented ctx");
    return mCtxNo;
}

// Set the context number of this argument
void
FunctionContext::setCtxNo(uint32_t CtxNo)
{
    mCtxNo = CtxNo;
}

} // namespace uir
