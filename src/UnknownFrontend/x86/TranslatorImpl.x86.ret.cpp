#include "TranslatorImpl.x86.h"

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

// Ret
bool
UnknownFrontendTranslatorImplX86::translateRetInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB)
{
    if (Insn->id != X86_INS_RET)
    {
        return false;
    }

    return true;
}

} // namespace ufrontend
