#  UnknownRebuilder
[![CMake-windows-latest](https://github.com/NewWorldComingSoon/UnknownRebuilder/actions/workflows/build-win.yml/badge.svg)](https://github.com/NewWorldComingSoon/UnknownRebuilder/actions/workflows/build-win.yml)

X86 native code rebuilder using UnknownIR(UIR)

## What's UIR?
Yet another Intermediate Representation(IR) called UnknownIR(UIR).

## Credit
- LLVM
- RetDec
- Capstone 
- Keystone

## Build
```
cmake -Bbuild -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_SHARED=OFF -DCAPSTONE_BUILD_STATIC_RUNTIME=ON -DLLVM_TARGETS_TO_BUILD=X86
```

This is currently an unfinished project.
