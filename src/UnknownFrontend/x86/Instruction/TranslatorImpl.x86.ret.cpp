#include <x86/TranslatorImpl.x86.h>

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

// Ret
bool
UnknownFrontendTranslatorImplX86::translateRetInstruction(const cs_insn *Insn, uir::BasicBlock *BB)
{
    if (Insn->id != X86_INS_RET)
    {
        return false;
    }

    bool TransRes = false;

    auto &X86Info = Insn->detail->x86;
    if (X86Info.op_count == 0)
    {
        // ret
        uir::IRBuilder IRB(BB);

        TransRes = IRB.createRetVoid(Insn->address) != nullptr;
    }
    else if (X86Info.op_count == 1)
    {
        // ret imm
        uir::IRBuilder IRB(BB);

        constexpr uint32_t TypeSize = 16;
        auto Imm = static_cast<uint64_t>(X86Info.operands[0].imm.imm);

        TransRes =
            IRB.createRetImm(
                uir::ConstantInt::get(uir::Type::getIntNTy(getContext(), TypeSize), unknown::APInt(TypeSize, Imm)),
                Insn->address) != nullptr;
    }
    else
    {
        assert("X86_INS_RET has only 0 or 1 operands" && false);
    }

    return TransRes;
}

} // namespace ufrontend
