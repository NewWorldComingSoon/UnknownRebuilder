#include <Function.h>
#include <BasicBlock.h>
#include <Argument.h>
#include <FunctionContext.h>
#include <Module.h>

#include <Context.h>
#include <ContextImpl/ContextImpl.h>

#include <Internal/InternalConfig/InternalConfig.h>

namespace uir {

////////////////////////////////////////////////////////////
//     Function
//
Function::Function(
    Context &C,
    const unknown::StringRef &FunctionName,
    Module *Parent,
    uint64_t FunctionAddressBegin,
    uint64_t FunctionAddressEnd) :
    Constant(Type::getFunctionTy(C), FunctionName),
    mFunctionName(FunctionName),
    mParent(Parent),
    mFunctionAddressBegin(FunctionAddressBegin),
    mFunctionAddressEnd(FunctionAddressEnd)
{
    // Clear ordered block name index.
    C.mImpl->mOrderedBlockNameIndex = 0;

    // Clear ordered local variable name index.
    C.mImpl->mOrderedLocalVarNameIndex = 0;
}

Function::~Function()
{
    // Clear all basic blocks.
    clearAllBasicBlock();
}

////////////////////////////////////////////////////////////
// Get/Set
// Get parent module
const Module *
Function::getParent() const
{
    return mParent;
}
Module *
Function::getParent()
{
    return mParent;
}

// Set parent module
void
Function::setParent(Module *Parent)
{
    mParent = Parent;
}

// Get the begin/end address of this function
uint64_t
Function::getFunctionBeginAddress() const
{
    return mFunctionAddressBegin;
}

// Get the begin/end address of this function
uint64_t
Function::getFunctionEndAddress() const
{
    return mFunctionAddressEnd;
}

// Set the begin address of this function
void
Function::setFunctionBeginAddress(uint64_t FunctionBeginAddress)
{
    mFunctionAddressBegin = FunctionBeginAddress;
}

// Set the end address of this function
void
Function::setFunctionEndAddress(uint64_t FunctionEndAddress)
{
    mFunctionAddressEnd = FunctionEndAddress;
}

// Get the entry block of this function
const BasicBlock &
Function::getEntryBlock() const
{
    return front();
}

// Get the entry block of this function
BasicBlock &
Function::getEntryBlock()
{
    return front();
}

// Get the name of this function
const std::string
Function::getFunctionName() const
{
    return mFunctionName;
}

// Set the name of this function
void
Function::setFunctionName(const unknown::StringRef &FunctionName)
{
    mFunctionName = FunctionName;
}

// Get the attributes of this function
const Function::FunctionAttributesListType &
Function::getFunctionAttributes() const
{
    return mFunctionAttributesList;
}

// Set the attributes of this function
void
Function::setFunctionAttributes(const Function::FunctionAttributesListType &FunctionAttributes)
{
    mFunctionAttributesList = FunctionAttributes;
}

////////////////////////////////////////////////////////////
// Function Attribute
// Add function attribute to this function.
void
Function::addFnAttr(const unknown::StringRef &FunctionAttribute)
{
    auto Iter = std::find(attr_begin(), attr_end(), FunctionAttribute);
    if (Iter == attr_end())
    {
        attr_push_back(FunctionAttribute);
    }
}

// Remove function attribute from this function.
void
Function::removeFnAttr(const unknown::StringRef &FunctionAttribute)
{
    auto Iter = std::find(attr_begin(), attr_end(), FunctionAttribute);
    if (Iter != attr_end())
    {
        attr_erase(Iter);
    }
}

// Check if this function has a specific attribute.
bool
Function::hasFnAttr(const unknown::StringRef &FunctionAttribute) const
{
    auto Iter = std::find(attr_begin(), attr_end(), FunctionAttribute);
    if (Iter != attr_end())
    {
        return true;
    }

    return false;
}

////////////////////////////////////////////////////////////
// Remove/Erase/Insert/Clear
// Remove the function from the its parent, but does not delete it.
void
Function::removeFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getFunctionList().empty())
    {
        return;
    }

    mParent->getFunctionList().remove(this);
}

// Remove the function from the its parent and delete it.
void
Function::eraseFromParent()
{
    if (mParent == nullptr)
    {
        return;
    }

    if (mParent->getFunctionList().empty())
    {
        return;
    }

    for (auto It = mParent->getFunctionList().begin(); It != mParent->getFunctionList().end(); ++It)
    {
        if (*It == this)
        {
            mParent->getFunctionList().erase(It);
            this->setParent(nullptr);
            --It;
        }
    }
}

// Insert a new basic block to this function
void
Function::insertBasicBlock(BasicBlock *BB)
{
    push_back(BB);
    BB->setParent(this);
}

// Insert a new arg to this function
void
Function::insertArgument(Argument *Arg)
{
    arg_push_back(Arg);
    Arg->setParent(this);
}

// Insert a new function context to this function
void
Function::insertFunctionContext(FunctionContext *FC)
{
    fc_push_back(FC);
    FC->setParent(this);
}

// Drop all blocks in this function.
void
Function::dropAllReferences()
{
    if (empty())
    {
        return;
    }

    for (auto BB : *this)
    {
        if (BB)
        {
            BB->dropAllReferences();
        }
    }

    for (auto ArgIt = arg_begin(); ArgIt != arg_end(); ++ArgIt)
    {
        auto Arg = *ArgIt;
        if (Arg)
        {
            Arg->dropAllReferences();
        }
    }

    for (auto FCIt = fc_begin(); FCIt != fc_end(); ++FCIt)
    {
        auto FC = *FCIt;
        if (FC)
        {
            FC->dropAllReferences();
        }
    }
}

// Clear all basic blocks.
void
Function::clearAllBasicBlock()
{
    if (empty())
    {
        return;
    }

    // Drop all blocks in this function
    dropAllReferences();

    // Clear all basic blocks
    for (auto BB : *this)
    {
        if (BB)
        {
            BB->clearAllInstructions();
        }
    }

    // Free all basic blocks
    std::vector<BasicBlock *> FreeBBList;
    for (auto BB : *this)
    {
        if (BB && BB->user_empty())
        {
            if (std::find(FreeBBList.begin(), FreeBBList.end(), BB) == FreeBBList.end())
            {
                FreeBBList.push_back(BB);
                delete BB;
            }
        }
    }

    // Free all args
    std::vector<Argument *> FreeArgsList;
    for (auto ArgIt = arg_begin(); ArgIt != arg_end(); ++ArgIt)
    {
        auto Arg = *ArgIt;
        if (Arg && Arg->user_empty())
        {
            if (std::find(FreeArgsList.begin(), FreeArgsList.end(), Arg) == FreeArgsList.end())
            {
                FreeArgsList.push_back(Arg);
                delete Arg;
            }
        }
    }

    // Free all FCs
    std::vector<FunctionContext *> FreeFCsList;
    for (auto FCIt = fc_begin(); FCIt != fc_end(); ++FCIt)
    {
        auto FC = *FCIt;
        if (FC && FC->user_empty())
        {
            if (std::find(FreeFCsList.begin(), FreeFCsList.end(), FC) == FreeFCsList.end())
            {
                FreeFCsList.push_back(FC);
                delete FC;
            }
        }
    }

    // Clear list
    clear();
    arg_clear();
    fc_clear();
}

////////////////////////////////////////////////////////////
// Static
// Generate a new function name by order
std::string
Function::generateOrderedFunctionName(Context &C)
{
    auto CurIdx = C.mImpl->mOrderedFunctionNameIndex++;
    return std::to_string(CurIdx);
}

////////////////////////////////////////////////////////////
// Virtual functions
// Get the readable name of this object
std::string
Function::getReadableName() const
{
    // function.func1
    std::string ReadableName = UIR_FUNCTION_VARIABLE_NAME_PREFIX;
    ReadableName += mFunctionName;

    return ReadableName;
}

// Get the property 'f' of the value
unknown::StringRef
Function::getPropertyFunction() const
{
    return "f";
}

// Get the property 'attributes' of the value
unknown::StringRef
Function::getPropertyAttributes() const
{
    return "attributes";
}

// Get the property 'arguments' of the value
unknown::StringRef
Function::getPropertyArguments() const
{
    return "arguments";
}

// Get the property 'context' of the value
unknown::StringRef
Function::getPropertyContext() const
{
    return "context";
}

// Print the function
void
Function::print(unknown::raw_ostream &OS, bool NewLine) const
{
    unknown::XMLPrinter Printer;
    print(Printer);
    OS << Printer.CStr();
}

// Print the function
void
Function::print(unknown::XMLPrinter &Printer) const
{
    Printer.OpenElement(getPropertyFunction().str().c_str());

    // name
    {
        Printer.PushAttribute(getPropertyName().str().c_str(), getReadableName().c_str());
    }

    // range
    {
        auto Range =
            std::format("0x{:X}", getFunctionBeginAddress()) + "-" + std::format("0x{:X}", getFunctionEndAddress());
        Printer.PushAttribute(getPropertyRange().str().c_str(), Range.c_str());
    }

    // attributes
    {
        std::stringstream SS;
        for (auto It = attr_begin(); It != attr_end(); ++It)
        {
            auto Attr = *It;
            if (Attr.empty())
            {
                continue;
            }

            SS << Attr;
            if (Attr != attr_back())
            {
                SS << UIR_SEPARATOR;
            }
        }

        Printer.PushAttribute(getPropertyAttributes().str().c_str(), SS.str().c_str());
    }

    // arguments
    {
        std::stringstream SS;
        for (auto It = arg_begin(); It != arg_end(); ++It)
        {
            auto Arg = *It;
            if (Arg == nullptr)
            {
                continue;
            }

            std::string ArgStr("");
            unknown::raw_string_ostream OSArgStr(ArgStr);
            Arg->print(OSArgStr, false);
            SS << OSArgStr.str();
            if (Arg != &arg_back())
            {
                SS << UIR_SEPARATOR;
            }
        }

        Printer.PushAttribute(getPropertyArguments().str().c_str(), SS.str().c_str());
    }

    // context
    {
        std::stringstream SS;
        for (auto It = fc_begin(); It != fc_end(); ++It)
        {
            auto FC = *It;
            if (FC == nullptr)
            {
                continue;
            }

            std::string FCStr("");
            unknown::raw_string_ostream OSFCStr(FCStr);
            FC->print(OSFCStr, false);
            SS << OSFCStr.str();

            if (FC != &fc_back())
            {
                SS << UIR_SEPARATOR;
            }
        }

        Printer.PushAttribute(getPropertyContext().str().c_str(), SS.str().c_str());
    }

    // extra
    {
        std::string Extra("");
        unknown::raw_string_ostream OSExtra(Extra);
        printExtraInfo(OSExtra);
        if (!OSExtra.str().empty())
        {
            Printer.PushAttribute(getPropertyExtra().str().c_str(), OSExtra.str().c_str());
        }
    }

    // comment
    {
        std::string Comment("");
        unknown::raw_string_ostream OSComment(Comment);
        printCommentInfo(OSComment);
        if (!OSComment.str().empty())
        {
            Printer.PushAttribute(getPropertyComment().str().c_str(), OSComment.str().c_str());
        }
    }

    // BB
    for (auto BB : *this)
    {
        if (BB == nullptr)
        {
            continue;
        }

        BB->print(Printer);
    }

    Printer.CloseElement();
}

} // namespace uir
