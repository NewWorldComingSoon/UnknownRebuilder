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

    // Get carry register
    virtual uint32_t getCarryRegister() override;
};

} // namespace unknown