#pragma once
#include <stdint.h>
#include <string>
#include <map>

#include <Type.h>

namespace uir {

class Context;

class ContextImpl
{
public:
    struct PointerTypeKey
    {
        Type *ElmtTy;
        uint32_t ElmtBits;
        bool operator<(const PointerTypeKey &other) const
        {
            uintptr_t u1 = reinterpret_cast<uintptr_t>(ElmtTy);
            uintptr_t u2 = reinterpret_cast<uintptr_t>(other.ElmtTy);
            if (u1 < u2)
            {
                return true;
            }
            else if (u1 > u2)
            {
                return false;
            }
            else
            {
                return ElmtBits < other.ElmtBits;
            }
        }
    };

private:
    Context &mContext;

public:
    // Basic type instances
    Type mVoidTy;
    Type mFloatTy;
    Type mDoubleTy;
    Type mLabelTy;
    Type mFunctionTy;

    // IntegerType instances
    IntegerType mInt1Ty;
    IntegerType mInt8Ty;
    IntegerType mInt16Ty;
    IntegerType mInt32Ty;
    IntegerType mInt64Ty;
    IntegerType mInt128Ty;

    // PointerType map
    std::map<PointerTypeKey, PointerType *> mPointerTypes;

public:
    explicit ContextImpl(Context &C);
    ~ContextImpl();

public:
    PointerType *getPointerType(Type *ElmtTy, uint32_t ElmtBits);
};

} // namespace uir