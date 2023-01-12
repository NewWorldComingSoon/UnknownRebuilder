#pragma once
#include <unknown/Target/Target.h>

namespace unknown {

class TargetX86 : public Target
{
public:
    TargetX86();
    virtual ~TargetX86();

public:
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) override;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) override;
};

} // namespace unknown
