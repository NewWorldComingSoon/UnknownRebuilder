#pragma once
#include <UnknownIR/Instruction.h>
#include <UnknownIR/BasicBlock.h>

namespace uir {

class IRBuilderDefaultInserter
{
protected:
    void InsertHelper(Instruction *I, uint64_t InstAddress, BasicBlock *BB, BasicBlock::iterator InsertPt) const;
};

class IRBuilderBase
{
protected:
    BasicBlock *mBB;
    BasicBlock::iterator mInsertPt;
    Context &mContext;

public:
    explicit IRBuilderBase(Context &C);

public:
    // Get/Set
    Context &getContext() const;
    BasicBlock *getInsertBlock() const;
    BasicBlock::iterator getInsertPoint() const;

public:
    // Insertion Point
    // Clear the insertion point
    void clearInsertionPoint();

    // Set the insertion point
    void setInsertPoint(BasicBlock *BB);
    void setInsertPoint(Instruction *I);
    void setInsertPoint(BasicBlock *BB, BasicBlock::iterator IT);
};

class IRBuilder : public IRBuilderBase, public IRBuilderDefaultInserter
{
public:
    explicit IRBuilder(Context &C);
    explicit IRBuilder(BasicBlock *BB);
    explicit IRBuilder(Instruction *I);
    explicit IRBuilder(BasicBlock *BB, BasicBlock::iterator IT);

public:
    // Insert
    template <typename InstTy>
    InstTy *insert(InstTy *I, uint64_t InstAddress = 0) const
    {
        this->InsertHelper(I, InstAddress, mBB, mInsertPt);
        return I;
    }

    Constant *insert(Constant *C) const { return C; }

public:
    // Create
    // Unknown
    UnknownInstruction *createUnknown(unknown::StringRef UnknownStr, uint64_t InstAddress);

    // Return
    ReturnInstruction *createRetVoid(uint64_t InstAddress);
    ReturnImmInstruction *createRetImm(ConstantInt *ImmConstantInt, uint64_t InstAddress);

    // Jmp
    JmpAddrInstruction *createJmpAddr(ConstantInt *JmpDest, uint64_t InstAddress);
    JmpBBInstruction *createJmpBB(BasicBlock *DestBB, uint64_t InstAddress);

    // Load
    LoadInstruction *createLoad(Value *Ptr, uint64_t InstAddress);

    // Store
    StoreInstruction *createStore(Value *Val, Value *Ptr, uint64_t InstAddress);

    // GetBitPtr
    GetBitPtrInstruction *createGetBitPtr(PointerType *ResType, Value *Ptr, Value *BitIndex, uint64_t InstAddress);
};

} // namespace uir
