# V8 Patch 移植记录：codegen_assembler

### 1. 冲突概况

- **原始位置 (2018):** `src/assembler.cc`、`src/assembler.h`、`src/code-stub-assembler.h`、`src/code-stub-assembler.cc`、`src/source-position-table.cc`、`src/source-position-table.h`、`src/external-reference-table.cc`、`src/external-reference-table.h`
- **现代位置 (2026):** `src/codegen/code-stub-assembler.h/.cc`、`src/codegen/source-position-table.h/.cc`、`src/codegen/external-reference-table.h/.cc`，以及旧 `assembler*` 的真实现代落点 `src/codegen/external-reference.h/.cc`
- **冲突原因:** codegen 文件已整体迁入 `src/codegen/`，而且 `ExternalReference` 的真实实现位置已经从旧 `assembler*` 演化出去；老补丁依赖的 source position 扩展、CSA helper、external reference hook 在现代树里都没有原位对应。

### 2. 逻辑映射 (Mapping)

- **补丁意图:** 给 source position、CSA、external reference 这些 codegen 入口重新建立现代路径上的稳定接口。
- **适配方案:** 具体到文件如下：
- **文件级处理: `src/codegen/source-position-table.h`**
  增加 `SourcePositionTableBuilder::NO_TAINT_TRACKING_INDEX`、带 `ast_taint_tracking_index` 的 `AddPosition(...)` 兼容重载、`SourcePositionTableIterator::ast_taint_tracking_index()`。
- **文件级处理: `src/codegen/source-position-table.cc`**
  将兼容重载实现为转发到现代 `AddPosition(...)`，当前忽略 legacy AST taint index。
- **文件级处理: `src/codegen/code-stub-assembler.h`**
  新增 `IncrementAndStoreTaintInstanceCounter(TNode<HeapObject> result)` 声明。
- **文件级处理: `src/codegen/code-stub-assembler.cc`**
  先把 `IncrementAndStoreTaintInstanceCounter(...)` 实现为 no-op；再把它挂到 `AllocateSeqOneByteString(...)`、`AllocateSeqTwoByteString(...)`、`AllocateSlicedString(...)` 这些现代字符串分配 helper。
- **文件级处理: `src/codegen/external-reference-table.h`**
  新增 `AddTaintTracking(Isolate* isolate, int* index)` 声明。
- **文件级处理: `src/codegen/external-reference-table.cc`**
  在 `Init(...)` 中接入 `AddTaintTracking(...)`，当前实现为 no-op。
- **文件级处理: `src/codegen/external-reference.h`**
  补 `ExternalReference::Create(tainttracking::InstanceCounter* counter)` 声明。
- **文件级处理: `src/codegen/external-reference.cc`**
  实现 `Create(tainttracking::InstanceCounter* counter)`，作为旧 `assembler.h/.cc` 对应功能的真实现代落点。

### 3. 代码对比 (简述)

| **NDSS 2018 (Old)** | **Modern V8 Adaptation (New)** |
| --- | --- |
| `AddPosition(..., ast_taint_tracking_index)` | 在 `src/codegen/source-position-table.h/.cc` 中补兼容重载 |
| `SourcePositionTableIterator::ast_taint_tracking_index()` | 在 `src/codegen/source-position-table.h/.cc` 中补兼容 accessor |
| `IncrementAndStoreTaintInstanceCounter(...)` | 在 `src/codegen/code-stub-assembler.h/.cc` 中补并挂接到字符串分配 helper |
| `assembler.h/.cc` 上的 `ExternalReference` 扩展 | remap 到 `src/codegen/external-reference.h/.cc` |
| `AddTaintTracking(Isolate*, int*)` | 在 `src/codegen/external-reference-table.h/.cc` 中补 hook |

### 4. 结论/风险

- **状态:** 已解决
- **风险:** 当前 codegen 层的大部分新增入口都是 no-op 或只保留兼容外形；如果后续要恢复 AST taint index 编码、instance counter 语义或更深层的 codegen taint 联动，还需要继续深入设计和验证。
