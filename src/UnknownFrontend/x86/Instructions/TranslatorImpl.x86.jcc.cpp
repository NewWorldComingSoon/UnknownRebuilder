#include <x86/TranslatorImpl.x86.h>

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

// Jcc
bool
UnknownFrontendTranslatorImplX86::translateJccInstruction(const cs_insn *Insn, uir::BasicBlock *BB)
{
    if (Insn->id != X86_INS_JAE && Insn->id != X86_INS_JA && Insn->id != X86_INS_JBE && Insn->id != X86_INS_JB &&
        Insn->id != X86_INS_JE && Insn->id != X86_INS_JGE && Insn->id != X86_INS_JG && Insn->id != X86_INS_JLE &&
        Insn->id != X86_INS_JL && Insn->id != X86_INS_JNE && Insn->id != X86_INS_JNO && Insn->id != X86_INS_JNP &&
        Insn->id != X86_INS_JNS && Insn->id != X86_INS_JO && Insn->id != X86_INS_JP && Insn->id != X86_INS_JS)
    {
        return false;
    }

    return true;
}

} // namespace ufrontend
