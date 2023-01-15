#include "TranslatorImpl.x86.h"

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

// Mov
bool
UnknownFrontendTranslatorImplX86::translateMovInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB)
{
    if (Insn->id != X86_INS_MOV)
    {
        return false;
    }

    return true;
}

} // namespace ufrontend
