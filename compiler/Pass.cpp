// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

#include "Pass.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/CodeGen/IntrinsicLowering.h>
#include <llvm/CodeGen/TargetLowering.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#if LLVM_VERSION_MAJOR < 14
#include <llvm/Support/TargetRegistry.h>
#else
#include <llvm/MC/TargetRegistry.h>
#endif

#include "Runtime.h"
#include "Symbolizer.h"

using namespace llvm;

#ifndef NDEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

char SymbolizeLegacyPass::ID = 0;

namespace {

static constexpr char kSymCtorName[] = "__sym_ctor";

bool instrumentModule(Module &M) {
  DEBUG(errs() << "Symbolizer module instrumentation\n");

  // Redirect calls to external functions to the corresponding wrappers and
  // rename internal functions.
  for (auto &function : M.functions()) {
    auto name = function.getName();
    if (isInterceptedFunction(function))
      function.setName(name + "_symbolized");
  } /*
    遍历模块中的函数，若为设定的待插桩函数，则进行改名处理（名字_symbolized）。
    待插桩函数列表在compiler/Runtime.cpp下的
  */

  // Insert a constructor that initializes the runtime and any globals.
  Function *ctor;
  std::tie(ctor, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, kSymCtorName, "_sym_initialize", {}, {});
  appendToGlobalCtors(M, ctor, 0);
  /*  在模块中插入一个构造函数__sym_ctor，该函数会在程序启动时调用_sym_initialize函数进行初始化。 */

  return true;
}

bool canLower(const CallInst *CI) {
  const Function *Callee = CI->getCalledFunction();
  if (!Callee)
    return false;

  switch (Callee->getIntrinsicID()) {
  case Intrinsic::expect:
  case Intrinsic::ctpop:
  case Intrinsic::ctlz:
  case Intrinsic::cttz:
  case Intrinsic::prefetch:
  case Intrinsic::pcmarker:
  case Intrinsic::dbg_declare:
  case Intrinsic::dbg_label:
  case Intrinsic::eh_typeid_for:
  case Intrinsic::annotation:
  case Intrinsic::ptr_annotation:
  case Intrinsic::assume:
#if LLVM_VERSION_MAJOR > 11
  case Intrinsic::experimental_noalias_scope_decl:
#endif
  case Intrinsic::var_annotation:
  case Intrinsic::sqrt:
  case Intrinsic::log:
  case Intrinsic::log2:
  case Intrinsic::log10:
  case Intrinsic::exp:
  case Intrinsic::exp2:
  case Intrinsic::pow:
  case Intrinsic::sin:
  case Intrinsic::cos:
  case Intrinsic::floor:
  case Intrinsic::ceil:
  case Intrinsic::trunc:
  case Intrinsic::round:
#if LLVM_VERSION_MAJOR > 10
  case Intrinsic::roundeven:
#endif
  case Intrinsic::copysign:
#if LLVM_VERSION_MAJOR < 16
  case Intrinsic::flt_rounds:
#else
  case Intrinsic::get_rounding:
#endif
  case Intrinsic::invariant_start:
  case Intrinsic::lifetime_start:
  case Intrinsic::invariant_end:
  case Intrinsic::lifetime_end:
    return true;
  default:
    return false;
  }

  llvm_unreachable("Control cannot reach here");
}

void liftInlineAssembly(CallInst *CI) {
  // TODO When we don't have to worry about the old pass manager anymore, move
  // the initialization to the pass constructor. (Currently there are two
  // passes, but only if we're on a recent enough LLVM...)

  Function *F = CI->getFunction();
  Module *M = F->getParent();
  auto triple = M->getTargetTriple();

  std::string error;
  auto target = TargetRegistry::lookupTarget(triple, error);
  if (!target) {
    errs() << "Warning: can't get target info to lift inline assembly\n";
    return;
  }
  /* 先获取module，然后获取triple。triple中记录了是给哪个平台生成代码的，
   * 并通过TargetRegistry::lookupTarget找到适配的目标架构。
   */
  auto cpu = F->getFnAttribute("target-cpu").getValueAsString();
  auto features = F->getFnAttribute("target-features").getValueAsString();
  /* 获取CPU参数和指令拓展 */

  std::unique_ptr<TargetMachine> TM(
      target->createTargetMachine(triple, cpu, features, TargetOptions(), {}));
  auto subTarget = TM->getSubtargetImpl(*F);
  if (subTarget == nullptr)
    return;

  auto targetLowering = subTarget->getTargetLowering();
  if (targetLowering == nullptr)
    return;

  targetLowering->ExpandInlineAsm(CI);
  /* 将CPU信息和拓展信息作为参数构建TargetMachine对象，并通过getSubtargetImpl()函数
   * 得到subTarget对象，最后从得到subTarget对象中获取TargetLowering对象，
   * 并调用ExpandInlineAsm()函数将内联汇编转换为LLVM IR。
   */
}

bool instrumentFunction(Function &F) {
  auto functionName = F.getName();
  if (functionName == kSymCtorName)
    return false; /* 获取函数名，若为__sym_ctor则跳过 */

  DEBUG(errs() << "Symbolizing function ");
  DEBUG(errs().write_escaped(functionName) << '\n');

  SmallVector<Instruction *, 0> allInstructions;
  allInstructions.reserve(F.getInstructionCount());
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  IntrinsicLowering IL(F.getParent()->getDataLayout());
  for (auto *I : allInstructions) {
    if (auto *CI = dyn_cast<CallInst>(I)) {
      if (canLower(CI)) {
        IL.LowerIntrinsicCall(CI);
      } else if (isa<InlineAsm>(CI->getCalledOperand())) {
        liftInlineAssembly(CI);
      }
    }
  }
  /* allInstructions存储了当前function的所有指令，然后开始对LLVM IR进行处理。
   * F.getParent()->getDataLayout()通过获取module的DataLayout从而获取目标机器的参数。
   * IntrinsicLowering对象负责将intrinsic调用转换成更底层的LLVM IR指令。
   * dyn_cast<CallInst>(I)确保提取出来的是CallInst对象。
   * 如果可以转换，直接转换成IR指令，否则就判断是不是内联汇编。
   * 是内联汇编的话，就通过liftInlineAssembly(CI)转换成IR。
   * */


  allInstructions.clear();
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  Symbolizer symbolizer(*F.getParent());
  /* Symbolizer对象用于对LLVM Module中的IR进行符号化 */
  symbolizer.symbolizeFunctionArguments(F);  // 对函数参数进行符号化处理

  for (auto &basicBlock : F)
    symbolizer.insertBasicBlockNotification(basicBlock);
  /* 遍历basic block，通过插入调用，使得runtime库能正确获得basic block的入口 */

  for (auto *instPtr : allInstructions) {
    symbolizer.visit(instPtr);
  }
  /* 遍历指令集并调用visit函数，所有实现都在compiler/Symbolizer.cpp中 */

  symbolizer.finalizePHINodes();
  symbolizer.shortCircuitExpressionUses();

  // DEBUG(errs() << F << '\n');
  assert(!verifyFunction(F, &errs()) &&
         "SymbolizePass produced invalid bitcode");

  return true;
}

} // namespace

bool SymbolizeLegacyPass::doInitialization(Module &M) {
  return instrumentModule(M);
}

bool SymbolizeLegacyPass::runOnFunction(Function &F) {
  return instrumentFunction(F);
}

#if LLVM_VERSION_MAJOR >= 13

PreservedAnalyses SymbolizePass::run(Function &F, FunctionAnalysisManager &) {
  return instrumentFunction(F) ? PreservedAnalyses::none()
                               : PreservedAnalyses::all();
}

PreservedAnalyses SymbolizePass::run(Module &M, ModuleAnalysisManager &) {
  return instrumentModule(M) ? PreservedAnalyses::none()
                             : PreservedAnalyses::all();
}

#endif
