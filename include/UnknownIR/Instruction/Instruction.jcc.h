#pragma once
#include <UnknownIR/InstructionBase.h>
#include <UnknownIR/Constant.h>

namespace uir {

class BasicBlock;
class FlagsVariable;

class JccAddrInstruction : public TerminatorInstruction
{
public:
    explicit JccAddrInstruction(ConstantInt *JccDest, ConstantInt *JccNormal, FlagsVariable *FlagsVar);
    virtual ~JccAddrInstruction();

public:
    // Virtual
    // Get the opcode name of this instruction
    virtual unknown::StringRef getOpcodeName() const override;

    // Get the default number of operands
    virtual uint32_t getDefaultNumberOfOperands() const override;

    // Is this instruction with flags?
    virtual bool hasFlags() const override;

    // Print the instruction
    virtual void print(unknown::raw_ostream &OS) const override;

public:
    // Get/Set
    // Get the JccDest constant int
    const ConstantInt *getJccDestConstantInt() const;

    // Get the JccNormal constant int
    const ConstantInt *getJccNormalConstantInt() const;

    // Set the JccDest constant int
    void setJccDestConstantInt(ConstantInt *JccDestConstantInt);

    // Set the JccNormal constant int
    void setJccNormalConstantInt(ConstantInt *JccNormalConstantInt);

public:
    // Static
    static JccAddrInstruction *get(ConstantInt *JccDest, ConstantInt *JccNormal, FlagsVariable *FlagsVar);
};

class JccBBInstruction : public TerminatorInstruction
{
public:
    explicit JccBBInstruction(BasicBlock *JccDestBB, BasicBlock *JccNormalBB, FlagsVariable *FlagsVar);
    virtual ~JccBBInstruction();

public:
    // Virtual
    // Get the opcode name of this instruction
    virtual unknown::StringRef getOpcodeName() const override;

    // Get the default number of operands
    virtual uint32_t getDefaultNumberOfOperands() const override;

    // Is this instruction with flags?
    virtual bool hasFlags() const override;

    // Print the instruction
    virtual void print(unknown::raw_ostream &OS) const override;

public:
    // Get/Set
    // Get the destination basic block.
    const BasicBlock *getDestinationBlock() const;

    // Get the normal basic block.
    const BasicBlock *getNormalBlock() const;

    // Set the destination basic block.
    void setDestinationBlock(BasicBlock *DestBB);

    // Set the destination basic block and update its predecessor.
    void setDestinationBlockAndUpdatePredecessor(BasicBlock *DestBB);

    // Set the normal basic block.
    void setNormalBlock(BasicBlock *NormalBB);

    // Set the normal basic block and update its predecessor.
    void setNormalBlockAndUpdatePredecessor(BasicBlock *NormalBB);

public:
    // Static
    static JccBBInstruction *get(BasicBlock *JccDestBB, BasicBlock *JccNormalBB, FlagsVariable *FlagsVar);
};

} // namespace uir
