#pragma once
#include <unknown/Target/Target.h>

namespace unknown {

class TargetX86 : public Target
{
public:
    explicit TargetX86(uint32_t ModeBits);
    virtual ~TargetX86();

public:
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) override;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) override;

    // Get the register parent id by register id
    virtual uint32_t getRegisterParentID(uint32_t RegID) override;

    // Get the register type bits by register id
    virtual uint32_t getRegisterTypeBits(uint32_t RegID) override;

    // Is the register type low 8 bits?
    virtual bool IsRegisterTypeLow8Bits(uint32_t RegID) override;

    // Is the register type high 8 bits?
    virtual bool IsRegisterTypeHigh8Bits(uint32_t RegID) override;

    // Get carry register
    virtual uint32_t getCarryRegister() override;

    // x86-specific pointer
    virtual const uint32_t getStackPointerRegister() const override;
    virtual const unknown::StringRef getStackPointerRegisterName() const override;
    virtual const uint32_t getBasePointerRegister() const override;
    virtual const unknown::StringRef getBasePointerRegisterName() const override;
};

} // namespace unknown
