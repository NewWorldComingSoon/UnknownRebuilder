#  UnknownRebuilder
[![CMake-windows-latest](https://github.com/NewWorldComingSoon/UnknownRebuilder/actions/workflows/CMake-windows-latest.yml/badge.svg)](https://github.com/NewWorldComingSoon/UnknownRebuilder/actions/workflows/CMake-windows-latest.yml)

X86 native code rebuilder using UnknownIR(UIR).

## What's UIR?
Yet another Intermediate Representation(IR) called UnknownIR(UIR).

## Credit
- [cmkr](https://github.com/build-cpp/cmkr)
- [LLVM](https://github.com/llvm/llvm-project)
- [RetDec](https://github.com/avast/retdec)
- [VTIL](https://github.com/vtil-project)
- [Capstone](https://github.com/NewWorldComingSoon/capstone-retdec) 
- [Keystone](https://github.com/NewWorldComingSoon/keystone-retdec)

## Build
Only tested on Windows, other systems have not been tested.
```
cmake -Bbuild -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_SHARED=OFF -DCAPSTONE_BUILD_STATIC_RUNTIME=ON -DLLVM_TARGETS_TO_BUILD=X86
```

## Note
This is currently an unfinished project.
