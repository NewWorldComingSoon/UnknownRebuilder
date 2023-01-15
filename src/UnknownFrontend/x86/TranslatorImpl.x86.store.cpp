#include "TranslatorImpl.x86.h"

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

// Store
bool
UnknownFrontendTranslatorImplX86::translateStoreInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB)
{
    if (Insn->id != X86_INS_MOV)
    {
        return false;
    }

    return true;
}

} // namespace ufrontend
