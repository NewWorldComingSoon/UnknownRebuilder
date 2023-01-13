#pragma once
#pragma once
#include <unknown/Target/Target.h>

namespace unknown {

class TargetARM : public Target
{
public:
    explicit TargetARM(uint32_t ModeBits);
    virtual ~TargetARM();

public:
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) override;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) override;

    // Get the register parent id by register id
    virtual uint32_t getRegisterParentID(uint32_t RegID) override;

    // Get the register type bits by register id
    virtual uint32_t getRegisterTypeBits(uint32_t RegID) override;

    // Get carry register
    virtual uint32_t getCarryRegister() override;

    // x86-specific pointer
    virtual const uint32_t getStackPointerRegister() const override { return 0; };
    virtual const unknown::StringRef getStackPointerRegisterName() const override { return ""; };
    virtual const uint32_t getBasePointerRegister() const override { return 0; };
    virtual const unknown::StringRef getBasePointerRegisterName() const override { return ""; };
};

} // namespace unknown