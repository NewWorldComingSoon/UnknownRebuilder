#include <x86/TranslatorImpl.x86.h>

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

// Unknown X86
bool
UnknownFrontendTranslatorImplX86::translateUnknownX86Instruction(const cs_insn *Insn, uir::BasicBlock *BB)
{
    std::string InstStr = "invalid";
    if (Insn->id != X86_INS_INVALID)
    {
        if (Insn->op_str[0] == 0)
        {
            InstStr = std::string(Insn->mnemonic);
        }
        else
        {
            InstStr = std::string(Insn->mnemonic) + " " + Insn->op_str;
        }
    }

    uir::IRBuilder IBR(BB);
    return IBR.createUnknown(InstStr, Insn->address) != nullptr;
}

} // namespace ufrontend
