#include "Target.x86.h"

#include <capstone/capstone.h>

namespace unknown {

TargetX86::TargetX86(uint32_t ModeBits) : Target(ModeBits)
{
    //
}

TargetX86::~TargetX86()
{
    //
}

// Get the register name by register id
std::string
TargetX86::getRegisterName(uint32_t RegID)
{
    if (mReg2Name.empty())
    {
        std::unordered_map<uint32_t, std::string> R2N = {
            // capstone register
            {X86_REG_AH, "ah"},
            {X86_REG_AL, "al"},
            {X86_REG_AX, "ax"},
            {X86_REG_BH, "bh"},
            {X86_REG_BL, "bl"},
            {X86_REG_BP, "bp"},
            {X86_REG_BPL, "bpl"},
            {X86_REG_BX, "bx"},
            {X86_REG_CH, "ch"},
            {X86_REG_CL, "cl"},
            {X86_REG_CS, "cs"},
            {X86_REG_CX, "cx"},
            {X86_REG_DH, "dh"},
            {X86_REG_DI, "di"},
            {X86_REG_DIL, "dil"},
            {X86_REG_DL, "dl"},
            {X86_REG_DS, "ds"},
            {X86_REG_DX, "dx"},
            {X86_REG_EAX, "eax"},
            {X86_REG_EBP, "ebp"},
            {X86_REG_EBX, "ebx"},
            {X86_REG_ECX, "ecx"},
            {X86_REG_EDI, "edi"},
            {X86_REG_EDX, "edx"},
            {X86_REG_EFLAGS, "flags"},
            {X86_REG_EIP, "eip"},
            {X86_REG_EIZ, "eiz"},
            {X86_REG_ES, "es"},
            {X86_REG_ESI, "esi"},
            {X86_REG_ESP, "esp"},
            {X86_REG_FPSW, "fpsw"},
            {X86_REG_FS, "fs"},
            {X86_REG_GS, "gs"},
            {X86_REG_IP, "ip"},
            {X86_REG_RAX, "rax"},
            {X86_REG_RBP, "rbp"},
            {X86_REG_RBX, "rbx"},
            {X86_REG_RCX, "rcx"},
            {X86_REG_RDI, "rdi"},
            {X86_REG_RDX, "rdx"},
            {X86_REG_RIP, "rip"},
            {X86_REG_RIZ, "riz"},
            {X86_REG_RSI, "rsi"},
            {X86_REG_RSP, "rsp"},
            {X86_REG_SI, "si"},
            {X86_REG_SIL, "sil"},
            {X86_REG_SP, "sp"},
            {X86_REG_SPL, "spl"},
            {X86_REG_SS, "ss"},
            {X86_REG_CR0, "cr0"},
            {X86_REG_CR1, "cr1"},
            {X86_REG_CR2, "cr2"},
            {X86_REG_CR3, "cr3"},
            {X86_REG_CR4, "cr4"},
            {X86_REG_CR5, "cr5"},
            {X86_REG_CR6, "cr6"},
            {X86_REG_CR7, "cr7"},
            {X86_REG_CR8, "cr8"},
            {X86_REG_CR9, "cr9"},
            {X86_REG_CR10, "cr10"},
            {X86_REG_CR11, "cr11"},
            {X86_REG_CR12, "cr12"},
            {X86_REG_CR13, "cr13"},
            {X86_REG_CR14, "cr14"},
            {X86_REG_CR15, "cr15"},
            {X86_REG_DR0, "dr0"},
            {X86_REG_DR1, "dr1"},
            {X86_REG_DR2, "dr2"},
            {X86_REG_DR3, "dr3"},
            {X86_REG_DR4, "dr4"},
            {X86_REG_DR5, "dr5"},
            {X86_REG_DR6, "dr6"},
            {X86_REG_DR7, "dr7"},
            {X86_REG_DR8, "dr8"},
            {X86_REG_DR9, "dr9"},
            {X86_REG_DR10, "dr10"},
            {X86_REG_DR11, "dr11"},
            {X86_REG_DR12, "dr12"},
            {X86_REG_DR13, "dr13"},
            {X86_REG_DR14, "dr14"},
            {X86_REG_DR15, "dr15"},
            {X86_REG_FP0, "fp0"},
            {X86_REG_FP1, "fp1"},
            {X86_REG_FP2, "fp2"},
            {X86_REG_FP3, "fp3"},
            {X86_REG_FP4, "fp4"},
            {X86_REG_FP5, "fp5"},
            {X86_REG_FP6, "fp6"},
            {X86_REG_FP7, "fp7"},
            {X86_REG_K0, "k0"},
            {X86_REG_K1, "k1"},
            {X86_REG_K2, "k2"},
            {X86_REG_K3, "k3"},
            {X86_REG_K4, "k4"},
            {X86_REG_K5, "k5"},
            {X86_REG_K6, "k6"},
            {X86_REG_K7, "k7"},
            {X86_REG_MM0, "mm0"},
            {X86_REG_MM1, "mm1"},
            {X86_REG_MM2, "mm2"},
            {X86_REG_MM3, "mm3"},
            {X86_REG_MM4, "mm4"},
            {X86_REG_MM5, "mm5"},
            {X86_REG_MM6, "mm6"},
            {X86_REG_MM7, "mm7"},
            {X86_REG_R8, "r8"},
            {X86_REG_R9, "r9"},
            {X86_REG_R10, "r10"},
            {X86_REG_R11, "r11"},
            {X86_REG_R12, "r12"},
            {X86_REG_R13, "r13"},
            {X86_REG_R14, "r14"},
            {X86_REG_R15, "r15"},
            {X86_REG_XMM0, "xmm0"},
            {X86_REG_XMM1, "xmm1"},
            {X86_REG_XMM2, "xmm2"},
            {X86_REG_XMM3, "xmm3"},
            {X86_REG_XMM4, "xmm4"},
            {X86_REG_XMM5, "xmm5"},
            {X86_REG_XMM6, "xmm6"},
            {X86_REG_XMM7, "xmm7"},
            {X86_REG_XMM8, "xmm8"},
            {X86_REG_XMM9, "xmm9"},
            {X86_REG_XMM10, "xmm10"},
            {X86_REG_XMM11, "xmm11"},
            {X86_REG_XMM12, "xmm12"},
            {X86_REG_XMM13, "xmm13"},
            {X86_REG_XMM14, "xmm14"},
            {X86_REG_XMM15, "xmm15"},
            {X86_REG_XMM16, "xmm16"},
            {X86_REG_XMM17, "xmm17"},
            {X86_REG_XMM18, "xmm18"},
            {X86_REG_XMM19, "xmm19"},
            {X86_REG_XMM20, "xmm20"},
            {X86_REG_XMM21, "xmm21"},
            {X86_REG_XMM22, "xmm22"},
            {X86_REG_XMM23, "xmm23"},
            {X86_REG_XMM24, "xmm24"},
            {X86_REG_XMM25, "xmm25"},
            {X86_REG_XMM26, "xmm26"},
            {X86_REG_XMM27, "xmm27"},
            {X86_REG_XMM28, "xmm28"},
            {X86_REG_XMM29, "xmm29"},
            {X86_REG_XMM30, "xmm30"},
            {X86_REG_XMM31, "xmm31"},
            {X86_REG_YMM0, "ymm0"},
            {X86_REG_YMM1, "ymm1"},
            {X86_REG_YMM2, "ymm2"},
            {X86_REG_YMM3, "ymm3"},
            {X86_REG_YMM4, "ymm4"},
            {X86_REG_YMM5, "ymm5"},
            {X86_REG_YMM6, "ymm6"},
            {X86_REG_YMM7, "ymm7"},
            {X86_REG_YMM8, "ymm8"},
            {X86_REG_YMM9, "ymm9"},
            {X86_REG_YMM10, "ymm10"},
            {X86_REG_YMM11, "ymm11"},
            {X86_REG_YMM12, "ymm12"},
            {X86_REG_YMM13, "ymm13"},
            {X86_REG_YMM14, "ymm14"},
            {X86_REG_YMM15, "ymm15"},
            {X86_REG_YMM16, "ymm16"},
            {X86_REG_YMM17, "ymm17"},
            {X86_REG_YMM18, "ymm18"},
            {X86_REG_YMM19, "ymm19"},
            {X86_REG_YMM20, "ymm20"},
            {X86_REG_YMM21, "ymm21"},
            {X86_REG_YMM22, "ymm22"},
            {X86_REG_YMM23, "ymm23"},
            {X86_REG_YMM24, "ymm24"},
            {X86_REG_YMM25, "ymm25"},
            {X86_REG_YMM26, "ymm26"},
            {X86_REG_YMM27, "ymm27"},
            {X86_REG_YMM28, "ymm28"},
            {X86_REG_YMM29, "ymm29"},
            {X86_REG_YMM30, "ymm30"},
            {X86_REG_YMM31, "ymm31"},
            {X86_REG_ZMM0, "zmm0"},
            {X86_REG_ZMM1, "zmm1"},
            {X86_REG_ZMM2, "zmm2"},
            {X86_REG_ZMM3, "zmm3"},
            {X86_REG_ZMM4, "zmm4"},
            {X86_REG_ZMM5, "zmm5"},
            {X86_REG_ZMM6, "zmm6"},
            {X86_REG_ZMM7, "zmm7"},
            {X86_REG_ZMM8, "zmm8"},
            {X86_REG_ZMM9, "zmm9"},
            {X86_REG_ZMM10, "zmm10"},
            {X86_REG_ZMM11, "zmm11"},
            {X86_REG_ZMM12, "zmm12"},
            {X86_REG_ZMM13, "zmm13"},
            {X86_REG_ZMM14, "zmm14"},
            {X86_REG_ZMM15, "zmm15"},
            {X86_REG_ZMM16, "zmm16"},
            {X86_REG_ZMM17, "zmm17"},
            {X86_REG_ZMM18, "zmm18"},
            {X86_REG_ZMM19, "zmm19"},
            {X86_REG_ZMM20, "zmm20"},
            {X86_REG_ZMM21, "zmm21"},
            {X86_REG_ZMM22, "zmm22"},
            {X86_REG_ZMM23, "zmm23"},
            {X86_REG_ZMM24, "zmm24"},
            {X86_REG_ZMM25, "zmm25"},
            {X86_REG_ZMM26, "zmm26"},
            {X86_REG_ZMM27, "zmm27"},
            {X86_REG_ZMM28, "zmm28"},
            {X86_REG_ZMM29, "zmm29"},
            {X86_REG_ZMM30, "zmm30"},
            {X86_REG_ZMM31, "zmm31"},
            {X86_REG_R8B, "r8b"},
            {X86_REG_R9B, "r9b"},
            {X86_REG_R10B, "r10b"},
            {X86_REG_R11B, "r11b"},
            {X86_REG_R12B, "r12b"},
            {X86_REG_R13B, "r13b"},
            {X86_REG_R14B, "r14b"},
            {X86_REG_R15B, "r15b"},
            {X86_REG_R8D, "r8d"},
            {X86_REG_R9D, "r9d"},
            {X86_REG_R10D, "r10d"},
            {X86_REG_R11D, "r11d"},
            {X86_REG_R12D, "r12d"},
            {X86_REG_R13D, "r13d"},
            {X86_REG_R14D, "r14d"},
            {X86_REG_R15D, "r15d"},
            {X86_REG_R8W, "r8w"},
            {X86_REG_R9W, "r9w"},
            {X86_REG_R10W, "r10w"},
            {X86_REG_R11W, "r11w"},
            {X86_REG_R12W, "r12w"},
            {X86_REG_R13W, "r13w"},
            {X86_REG_R14W, "r14w"},
            {X86_REG_R15W, "r15w"},

            // x86_reg_rflags
            //
            {X86_REG_CF, "cf"},
            {X86_REG_PF, "pf"},
            {X86_REG_AF, "af"},
            {X86_REG_ZF, "zf"},
            {X86_REG_SF, "sf"},
            {X86_REG_TF, "tf"},
            {X86_REG_IF, "if"},
            {X86_REG_DF, "df"},
            {X86_REG_OF, "of"},
            {X86_REG_IOPL, "iopl"},
            {X86_REG_NT, "nt"},
            {X86_REG_RF, "rf"},
            {X86_REG_VM, "vm"},
            {X86_REG_AC, "ac"},
            {X86_REG_VIF, "vif"},
            {X86_REG_VIP, "vip"},
            {X86_REG_ID, "id"},

            // x87_reg_status
            //
            {X87_REG_IE, "fpu_stat_IE"},
            {X87_REG_DE, "fpu_stat_DE"},
            {X87_REG_ZE, "fpu_stat_ZE"},
            {X87_REG_OE, "fpu_stat_OE"},
            {X87_REG_UE, "fpu_stat_UE"},
            {X87_REG_PE, "fpu_stat_PE"},
            {X87_REG_SF, "fpu_stat_SF"},
            {X87_REG_ES, "fpu_stat_ES"},
            {X87_REG_C0, "fpu_stat_C0"},
            {X87_REG_C1, "fpu_stat_C1"},
            {X87_REG_C2, "fpu_stat_C2"},
            {X87_REG_C3, "fpu_stat_C3"},
            {X87_REG_TOP, "fpu_stat_TOP"},
            {X87_REG_B, "fpu_stat_B"},

            // x87_reg_control
            //
            {X87_REG_IM, "fpu_control_IM"},
            {X87_REG_DM, "fpu_control_DM"},
            {X87_REG_ZM, "fpu_control_ZM"},
            {X87_REG_OM, "fpu_control_OM"},
            {X87_REG_UM, "fpu_control_UM"},
            {X87_REG_PM, "fpu_control_PM"},
            {X87_REG_PC, "fpu_control_PC"},
            {X87_REG_RC, "fpu_control_RC"},
            {X87_REG_X, "fpu_control_X"},

            // FPU data registers
            // They are named as ST(X) in Capstone, which is not good for us.
            //
            {X86_REG_ST0, "st0"},
            {X86_REG_ST1, "st1"},
            {X86_REG_ST2, "st2"},
            {X86_REG_ST3, "st3"},
            {X86_REG_ST4, "st4"},
            {X86_REG_ST5, "st5"},
            {X86_REG_ST6, "st6"},
            {X86_REG_ST7, "st7"},
        };

        mReg2Name = std::move(R2N);
    }

    auto It = mReg2Name.find(RegID);
    if (It == mReg2Name.end())
    {
        return "";
    }
    else
    {
        return It->second;
    }
}

// Get the register id by register name
uint32_t
TargetX86::getRegisterID(const std::string &RegName)
{
    if (mName2Reg.empty())
    {
        getRegisterName(X86_REG_EAX);
        for (auto &Item : mReg2Name)
        {
            mName2Reg.insert({Item.second, Item.first});
        }
    }

    auto It = mName2Reg.find(RegName);
    if (It == mName2Reg.end())
    {
        return X86_REG_INVALID;
    }
    else
    {
        return It->second;
    }
}

// Get the register parent id by register id
uint32_t
TargetX86::getRegisterParentID(uint32_t RegID)
{
    if (mReg2ParentReg.empty())
    {
        std::vector<std::vector<x86_reg>> RSS64 = {
            {X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_EAX, X86_REG_RAX},
            {X86_REG_CH, X86_REG_CL, X86_REG_CX, X86_REG_ECX, X86_REG_RCX},
            {X86_REG_DH, X86_REG_DL, X86_REG_DX, X86_REG_EDX, X86_REG_RDX},
            {X86_REG_BH, X86_REG_BL, X86_REG_BX, X86_REG_EBX, X86_REG_RBX},
            {X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP},
            {X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP},
            {X86_REG_SIL, X86_REG_SI, X86_REG_ESI, X86_REG_RSI},
            {X86_REG_DIL, X86_REG_DI, X86_REG_EDI, X86_REG_RDI},
            {X86_REG_IP, X86_REG_EIP, X86_REG_RIP},
            {X86_REG_EIZ, X86_REG_RIZ},
            {X86_REG_R8B, X86_REG_R8W, X86_REG_R8D, X86_REG_R8},
            {X86_REG_R9B, X86_REG_R9W, X86_REG_R9D, X86_REG_R9},
            {X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10},
            {X86_REG_R11B, X86_REG_R11W, X86_REG_R11D, X86_REG_R11},
            {X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12},
            {X86_REG_R13B, X86_REG_R13W, X86_REG_R13D, X86_REG_R13},
            {X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14},
            {X86_REG_R15B, X86_REG_R15W, X86_REG_R15D, X86_REG_R15}};

        std::vector<std::vector<x86_reg>> RSS32 = {
            {X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_EAX},
            {X86_REG_CH, X86_REG_CL, X86_REG_CX, X86_REG_ECX},
            {X86_REG_DH, X86_REG_DL, X86_REG_DX, X86_REG_EDX},
            {X86_REG_BH, X86_REG_BL, X86_REG_BX, X86_REG_EBX},
            {X86_REG_SPL, X86_REG_SP, X86_REG_ESP},
            {X86_REG_BPL, X86_REG_BP, X86_REG_EBP},
            {X86_REG_SIL, X86_REG_SI, X86_REG_ESI},
            {X86_REG_DIL, X86_REG_DI, X86_REG_EDI},
            {X86_REG_IP, X86_REG_EIP},
            {X86_REG_EIZ}};

        auto InitReg2ParentReg = [this](std::vector<std::vector<x86_reg>> &RSS) {
            for (std::vector<x86_reg> &RS : RSS)
            {
                for (x86_reg R : RS)
                {
                    mReg2ParentReg[R] = RS.back();
                }
            }
        };

        if (mModeBits == 64)
        {
            InitReg2ParentReg(RSS64);
        }
        else if (mModeBits == 32)
        {
            InitReg2ParentReg(RSS32);
        }
        else
        {
            // TODO
        }
    }

    auto It = mReg2ParentReg.find(RegID);
    if (It == mReg2ParentReg.end())
    {
        return X86_REG_INVALID;
    }
    else
    {
        return It->second;
    }
}

// Get the register type bits by register id
uint32_t
TargetX86::getRegisterTypeBits(uint32_t RegID)
{
    if (mReg2TypeBits.empty())
    {
        std::unordered_map<uint32_t, uint32_t> R2TB = {
            // x86_reg
            //
            {X86_REG_AH, 8},
            {X86_REG_AL, 8},
            {X86_REG_CH, 8},
            {X86_REG_CL, 8},
            {X86_REG_DH, 8},
            {X86_REG_DL, 8},
            {X86_REG_BH, 8},
            {X86_REG_BL, 8},
            {X86_REG_SPL, 8},
            {X86_REG_BPL, 8},
            {X86_REG_DIL, 8},
            {X86_REG_SIL, 8},
            {X86_REG_R8B, 8},
            {X86_REG_R9B, 8},
            {X86_REG_R10B, 8},
            {X86_REG_R11B, 8},
            {X86_REG_R12B, 8},
            {X86_REG_R13B, 8},
            {X86_REG_R14B, 8},
            {X86_REG_R15B, 8},

            {X86_REG_AX, 16},
            {X86_REG_CX, 16},
            {X86_REG_DX, 16},
            {X86_REG_BP, 16},
            {X86_REG_BX, 16},
            {X86_REG_DI, 16},
            {X86_REG_SP, 16},
            {X86_REG_SI, 16},
            {X86_REG_SS, 16},
            {X86_REG_CS, 16},
            {X86_REG_DS, 16},
            {X86_REG_ES, 16},
            {X86_REG_FS, 16},
            {X86_REG_GS, 16},
            {X86_REG_R8W, 16},
            {X86_REG_R9W, 16},
            {X86_REG_R10W, 16},
            {X86_REG_R11W, 16},
            {X86_REG_R12W, 16},
            {X86_REG_R13W, 16},
            {X86_REG_R14W, 16},
            {X86_REG_R15W, 16},
            {X86_REG_IP, 16},

            {X86_REG_EAX, 32},
            {X86_REG_EBP, 32},
            {X86_REG_EBX, 32},
            {X86_REG_ECX, 32},
            {X86_REG_EDI, 32},
            {X86_REG_EDX, 32},
            {X86_REG_ESI, 32},
            {X86_REG_ESP, 32},
            {X86_REG_R8D, 32},
            {X86_REG_R9D, 32},
            {X86_REG_R10D, 32},
            {X86_REG_R11D, 32},
            {X86_REG_R12D, 32},
            {X86_REG_R13D, 32},
            {X86_REG_R14D, 32},
            {X86_REG_R15D, 32},
            {X86_REG_EIP, 32},
            {X86_REG_EIZ, 32},

            {X86_REG_RAX, 64},
            {X86_REG_RBP, 64},
            {X86_REG_RBX, 64},
            {X86_REG_RCX, 64},
            {X86_REG_RDI, 64},
            {X86_REG_RDX, 64},
            {X86_REG_RIP, 64},
            {X86_REG_RIZ, 64},
            {X86_REG_RSI, 64},
            {X86_REG_RSP, 64},
            {X86_REG_R8, 64},
            {X86_REG_R9, 64},
            {X86_REG_R10, 64},
            {X86_REG_R11, 64},
            {X86_REG_R12, 64},
            {X86_REG_R13, 64},
            {X86_REG_R14, 64},
            {X86_REG_R15, 64},

            {X86_REG_ST0, 80},
            {X86_REG_ST1, 80},
            {X86_REG_ST2, 80},
            {X86_REG_ST3, 80},
            {X86_REG_ST4, 80},
            {X86_REG_ST5, 80},
            {X86_REG_ST6, 80},
            {X86_REG_ST7, 80},

            {X86_REG_FP0, 64},
            {X86_REG_FP1, 64},
            {X86_REG_FP2, 64},
            {X86_REG_FP3, 64},
            {X86_REG_FP4, 64},
            {X86_REG_FP5, 64},
            {X86_REG_FP6, 64},
            {X86_REG_FP7, 64},

            {X86_REG_EFLAGS, mModeBits},
            {X86_REG_DR0, mModeBits},
            {X86_REG_DR1, mModeBits},
            {X86_REG_DR2, mModeBits},
            {X86_REG_DR3, mModeBits},
            {X86_REG_DR4, mModeBits},
            {X86_REG_DR5, mModeBits},
            {X86_REG_DR6, mModeBits},
            {X86_REG_DR7, mModeBits},
            {X86_REG_DR8, mModeBits},
            {X86_REG_DR9, mModeBits},
            {X86_REG_DR10, mModeBits},
            {X86_REG_DR11, mModeBits},
            {X86_REG_DR12, mModeBits},
            {X86_REG_DR13, mModeBits},
            {X86_REG_DR14, mModeBits},
            {X86_REG_DR15, mModeBits},

            {X86_REG_CR0, mModeBits},
            {X86_REG_CR1, mModeBits},
            {X86_REG_CR2, mModeBits},
            {X86_REG_CR3, mModeBits},
            {X86_REG_CR4, mModeBits},
            {X86_REG_CR5, mModeBits},
            {X86_REG_CR6, mModeBits},
            {X86_REG_CR7, mModeBits},
            {X86_REG_CR8, mModeBits},
            {X86_REG_CR9, mModeBits},
            {X86_REG_CR10, mModeBits},
            {X86_REG_CR11, mModeBits},
            {X86_REG_CR12, mModeBits},
            {X86_REG_CR13, mModeBits},
            {X86_REG_CR14, mModeBits},
            {X86_REG_CR15, mModeBits},

            {X86_REG_FPSW, mModeBits},

            // opmask registers (AVX-512)
            {X86_REG_K0, 64},
            {X86_REG_K1, 64},
            {X86_REG_K2, 64},
            {X86_REG_K3, 64},
            {X86_REG_K4, 64},
            {X86_REG_K5, 64},
            {X86_REG_K6, 64},
            {X86_REG_K7, 64},

            // MMX
            {X86_REG_MM0, 64},
            {X86_REG_MM1, 64},
            {X86_REG_MM2, 64},
            {X86_REG_MM3, 64},
            {X86_REG_MM4, 64},
            {X86_REG_MM5, 64},
            {X86_REG_MM6, 64},
            {X86_REG_MM7, 64},

            // XMM
            {X86_REG_XMM0, 128},
            {X86_REG_XMM1, 128},
            {X86_REG_XMM2, 128},
            {X86_REG_XMM3, 128},
            {X86_REG_XMM4, 128},
            {X86_REG_XMM5, 128},
            {X86_REG_XMM6, 128},
            {X86_REG_XMM7, 128},
            {X86_REG_XMM8, 128},
            {X86_REG_XMM9, 128},
            {X86_REG_XMM10, 128},
            {X86_REG_XMM11, 128},
            {X86_REG_XMM12, 128},
            {X86_REG_XMM13, 128},
            {X86_REG_XMM14, 128},
            {X86_REG_XMM15, 128},
            {X86_REG_XMM16, 128},
            {X86_REG_XMM17, 128},
            {X86_REG_XMM18, 128},
            {X86_REG_XMM19, 128},
            {X86_REG_XMM20, 128},
            {X86_REG_XMM21, 128},
            {X86_REG_XMM22, 128},
            {X86_REG_XMM23, 128},
            {X86_REG_XMM24, 128},
            {X86_REG_XMM25, 128},
            {X86_REG_XMM26, 128},
            {X86_REG_XMM27, 128},
            {X86_REG_XMM28, 128},
            {X86_REG_XMM29, 128},
            {X86_REG_XMM30, 128},
            {X86_REG_XMM31, 128},

            // YMM
            {X86_REG_YMM0, 256},
            {X86_REG_YMM1, 256},
            {X86_REG_YMM2, 256},
            {X86_REG_YMM3, 256},
            {X86_REG_YMM4, 256},
            {X86_REG_YMM5, 256},
            {X86_REG_YMM6, 256},
            {X86_REG_YMM7, 256},
            {X86_REG_YMM8, 256},
            {X86_REG_YMM9, 256},
            {X86_REG_YMM10, 256},
            {X86_REG_YMM11, 256},
            {X86_REG_YMM12, 256},
            {X86_REG_YMM13, 256},
            {X86_REG_YMM14, 256},
            {X86_REG_YMM15, 256},
            {X86_REG_YMM16, 256},
            {X86_REG_YMM17, 256},
            {X86_REG_YMM18, 256},
            {X86_REG_YMM19, 256},
            {X86_REG_YMM20, 256},
            {X86_REG_YMM21, 256},
            {X86_REG_YMM22, 256},
            {X86_REG_YMM23, 256},
            {X86_REG_YMM24, 256},
            {X86_REG_YMM25, 256},
            {X86_REG_YMM26, 256},
            {X86_REG_YMM27, 256},
            {X86_REG_YMM28, 256},
            {X86_REG_YMM29, 256},
            {X86_REG_YMM30, 256},
            {X86_REG_YMM31, 256},

            // ZMM
            {X86_REG_ZMM0, 512},
            {X86_REG_ZMM1, 512},
            {X86_REG_ZMM2, 512},
            {X86_REG_ZMM3, 512},
            {X86_REG_ZMM4, 512},
            {X86_REG_ZMM5, 512},
            {X86_REG_ZMM6, 512},
            {X86_REG_ZMM7, 512},
            {X86_REG_ZMM8, 512},
            {X86_REG_ZMM9, 512},
            {X86_REG_ZMM10, 512},
            {X86_REG_ZMM11, 512},
            {X86_REG_ZMM12, 512},
            {X86_REG_ZMM13, 512},
            {X86_REG_ZMM14, 512},
            {X86_REG_ZMM15, 512},
            {X86_REG_ZMM16, 512},
            {X86_REG_ZMM17, 512},
            {X86_REG_ZMM18, 512},
            {X86_REG_ZMM19, 512},
            {X86_REG_ZMM20, 512},
            {X86_REG_ZMM21, 512},
            {X86_REG_ZMM22, 512},
            {X86_REG_ZMM23, 512},
            {X86_REG_ZMM24, 512},
            {X86_REG_ZMM25, 512},
            {X86_REG_ZMM26, 512},
            {X86_REG_ZMM27, 512},
            {X86_REG_ZMM28, 512},
            {X86_REG_ZMM29, 512},
            {X86_REG_ZMM30, 512},
            {X86_REG_ZMM31, 512},

            // x86_reg_rflags
            //
            {X86_REG_CF, 1},
            {X86_REG_PF, 1},
            {X86_REG_AF, 1},
            {X86_REG_ZF, 1},
            {X86_REG_SF, 1},
            {X86_REG_TF, 1},
            {X86_REG_IF, 1},
            {X86_REG_DF, 1},
            {X86_REG_OF, 1},
            {X86_REG_IOPL, 2},
            {X86_REG_NT, 1},
            {X86_REG_RF, 1},
            {X86_REG_VM, 1},
            {X86_REG_AC, 1},
            {X86_REG_VIF, 1},
            {X86_REG_VIP, 1},
            {X86_REG_ID, 1},

            // x87_reg_status
            //
            {X87_REG_IE, 1},
            {X87_REG_DE, 1},
            {X87_REG_ZE, 1},
            {X87_REG_OE, 1},
            {X87_REG_UE, 1},
            {X87_REG_PE, 1},
            {X87_REG_SF, 1},
            {X87_REG_ES, 1},
            {X87_REG_C0, 1},
            {X87_REG_C1, 1},
            {X87_REG_C2, 1},
            {X87_REG_C3, 1},
            {X87_REG_TOP, 3},
            {X87_REG_B, 1},

            // x87_reg_control
            //
            {X87_REG_IM, 1},
            {X87_REG_DM, 1},
            {X87_REG_ZM, 1},
            {X87_REG_OM, 1},
            {X87_REG_UM, 1},
            {X87_REG_PM, 1},
            {X87_REG_PC, 2},
            {X87_REG_RC, 2},
            {X87_REG_X, 1},
        };

        mReg2TypeBits = std::move(R2TB);
    }

    auto It = mReg2TypeBits.find(RegID);
    if (It == mReg2TypeBits.end())
    {
        return mModeBits;
    }
    else
    {
        return It->second;
    }
}

// Is the register type low 8 bits?
bool
TargetX86::IsRegisterTypeLow8Bits(uint32_t RegID)
{
    if (mTypeLow8Bits.empty())
    {
        std::unordered_map<uint32_t, bool> TL8B = {
            {X86_REG_AH, false},  {X86_REG_AL, true},   {X86_REG_CH, false},  {X86_REG_CL, true},
            {X86_REG_DH, false},  {X86_REG_DL, true},   {X86_REG_BH, false},  {X86_REG_BL, true},
            {X86_REG_SPL, true},  {X86_REG_BPL, true},  {X86_REG_DIL, true},  {X86_REG_SIL, true},
            {X86_REG_R8B, true},  {X86_REG_R9B, true},  {X86_REG_R10B, true}, {X86_REG_R11B, true},
            {X86_REG_R12B, true}, {X86_REG_R13B, true}, {X86_REG_R14B, true}, {X86_REG_R15B, true}};
        mTypeLow8Bits = std::move(TL8B);
    }

    auto It = mTypeLow8Bits.find(RegID);
    if (It == mTypeLow8Bits.end())
    {
        return It->second;
    }
    else
    {
        return false;
    }
}

// Is the register type high 8 bits?
bool
TargetX86::IsRegisterTypeHigh8Bits(uint32_t RegID)
{
    if (mTypeHigh8Bits.empty())
    {
        IsRegisterTypeLow8Bits(X86_REG_AH);
        for (auto &Item : mTypeLow8Bits)
        {
            mTypeHigh8Bits.insert({Item.first, !Item.second});
        }
    }

    auto It = mTypeHigh8Bits.find(RegID);
    if (It == mTypeHigh8Bits.end())
    {
        return It->second;
    }
    else
    {
        return false;
    }
}

// Get carry register
uint32_t
TargetX86::getCarryRegister()
{
    return X86_REG_CF;
}

// x86-specific pointer
const uint32_t
TargetX86::getStackPointerRegister() const
{
    switch (mModeBits)
    {
    case 32:
        return X86_REG_ESP;
    case 64:
        return X86_REG_RSP;
    }

    return 0;
}

const unknown::StringRef
TargetX86::getStackPointerRegisterName() const
{
    switch (mModeBits)
    {
    case 32:
        return "ESP";
    case 64:
        return "RSP";
    }

    return "";
}

const uint32_t
TargetX86::getBasePointerRegister() const
{
    switch (mModeBits)
    {
    case 32:
        return X86_REG_EBP;
    case 64:
        return X86_REG_RBP;
    }

    return 0;
}

const unknown::StringRef
TargetX86::getBasePointerRegisterName() const
{
    switch (mModeBits)
    {
    case 32:
        return "EBP";
    case 64:
        return "RBP";
    }

    return "";
}

} // namespace unknown
