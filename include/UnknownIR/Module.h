#pragma once
#include <unordered_set>

#include <UnknownIR/Function.h>
#include <UnknownIR/GlobalVariable.h>

namespace uir {

class Module
{
protected:
    Context &mContext;
    std::string mModuleName;
    std::unordered_set<Function *> mFunctionList;
    std::unordered_set<GlobalVariable *> mGlobalVariableList;

public:
    explicit Module(Context &C, const char *ModuleName);
    virtual ~Module();

public:
    // List
    // Get function list
    const std::unordered_set<Function *> &getFunctionList() const;
    std::unordered_set<Function *> &getFunctionList();

    // Get global variable list
    const std::unordered_set<GlobalVariable *> &getGlobalVariableList() const;
    std::unordered_set<GlobalVariable *> &getGlobalVariableList();

public:
    // Context
    Context &getContext() const;

public:
    // Iterators
    // Function Iterators
    using iterator = std::unordered_set<Function *>::iterator;
    using const_iterator = std::unordered_set<Function *>::const_iterator;
    iterator begin() { return mFunctionList.begin(); }
    const_iterator begin() const { return mFunctionList.cbegin(); }
    iterator end() { return mFunctionList.end(); }
    const_iterator end() const { return mFunctionList.cend(); }
    size_t size() const { return mFunctionList.size(); }
    bool empty() const { return mFunctionList.empty(); }

    // Function Iterators
    using global_iterator = std::unordered_set<GlobalVariable *>::iterator;
    using const_global_iterator = std::unordered_set<GlobalVariable *>::const_iterator;
    global_iterator global_begin() { return mGlobalVariableList.begin(); }
    const_global_iterator global_begin() const { return mGlobalVariableList.cbegin(); }
    global_iterator global_end() { return mGlobalVariableList.end(); }
    const_global_iterator global_end() const { return mGlobalVariableList.cend(); }
    size_t global_size() const { return mGlobalVariableList.size(); }
    bool global_empty() const { return mGlobalVariableList.empty(); }

public:
    // Get/Set
    // Get/Set the name of module
    std::string getModuleName() const;
    void setModuleName(const char *ModuleName);

    // Get the specified function by name in the module
    Function *getFunction(const char *FunctionName) const;

    // Insert a function into the module
    void insertFunction(Function *Function);
};

} // namespace uir
