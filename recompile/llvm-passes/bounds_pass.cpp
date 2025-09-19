#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
class ReBoundsPass : public PassInfoMixin<ReBoundsPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const DataLayout &DL = M.getDataLayout();
    std::string Buf;
    llvm::raw_string_ostream OS(Buf);

    unsigned Count = 0;
    const unsigned MaxEntries = 10000; // cap per spec
    for (GlobalVariable &G : M.globals()) {
      if (Count >= MaxEntries) break;
      if (G.isDeclaration()) continue;
      if (!G.hasInitializer()) continue;
      Type *Ty = G.getValueType();
      if (!Ty) continue;
      uint64_t Size = DL.getTypeAllocSize(Ty);
      // Emit: name size\n
      OS << G.getName() << " " << Size << "\n";
      ++Count;
    }
    OS.flush();

    if (!Buf.empty()) {
      LLVMContext &Ctx = M.getContext();
      Constant *Arr = ConstantDataArray::getString(Ctx, Buf, false);
      auto *Note = new GlobalVariable(
          M, Arr->getType(), /*isConstant=*/true, GlobalValue::InternalLinkage,
          Arr, "re_bounds_note");
      Note->setSection(".note.re.bounds");
      Note->setAlignment(Align(1));
    }

    return PreservedAnalyses::none();
  }
};
}

llvm::PassPluginLibraryInfo getReBoundsPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "ReBoundsPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "re-bounds-pass") {
                    MPM.addPass(ReBoundsPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getReBoundsPassPluginInfo();
}


