#include <FunctionContext.h>
#include <Function.h>

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

////////////////////////////////////////////////////////////
// Remove/Erase
// Remove this context from its parent, but does not delete it.
void
FunctionContext::removeFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getFunctionContextList().empty())
    {
        return;
    }

    mParent->getFunctionContextList().remove(this);
}

// Remove this context from its parent and delete it.
void
FunctionContext::eraseFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getFunctionContextList().empty())
    {
        return;
    }

    for (auto It = mParent->getFunctionContextList().begin(); It != mParent->getFunctionContextList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getFunctionContextList().erase(It);
            this->setParent(nullptr);
            --It;
        }
    }
}
////////////////////////////////////////////////////////////
// Virtual functions
// Get the property 'ctx' of the value
unknown::StringRef
FunctionContext::getPropertyFC() const
{
    return "ctx";
}

// Get the property 'ctxno' of the value
unknown::StringRef
FunctionContext::getPropertyFCNo() const
{
    return "ctxno";
}

// Print the fc
void
FunctionContext::print(unknown::raw_ostream &OS, bool NewLine) const
{
    unknown::XMLPrinter Printer;
    print(Printer);
    OS << Printer.CStr();
}

// Print the fc
void
FunctionContext::print(unknown::XMLPrinter &Printer) const
{
    Printer.OpenElement(getPropertyFC().data());

    // name
    {
        Printer.PushAttribute(getPropertyName().data(), getReadableName().c_str());
    }

    // ctxno
    {
        Printer.PushAttribute(getPropertyFCNo().data(), std::format("{}", mCtxNo).c_str());
    }

    // extra
    {
        std::string Extra("");
        unknown::raw_string_ostream OSExtra(Extra);
        printExtraInfo(OSExtra);
        if (!OSExtra.str().empty())
        {
            Printer.PushAttribute(getPropertyExtra().data(), OSExtra.str().c_str());
        }
    }

    // comment
    {
        std::string Comment("");
        unknown::raw_string_ostream OSComment(Comment);
        printCommentInfo(OSComment);
        if (!OSComment.str().empty())
        {
            Printer.PushAttribute(getPropertyComment().data(), OSComment.str().c_str());
        }
    }

    Printer.CloseElement();
}

////////////////////////////////////////////////////////////
// Static
FunctionContext *
FunctionContext::get(Type *Ty, const unknown::StringRef &CtxName, Function *F, uint32_t CtxNo)
{
    return new FunctionContext(Ty, CtxName, F, CtxNo);
}

} // namespace uir
