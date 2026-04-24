# V8 Patch 移植记录：objects_context

### 1. 冲突概况

- **原始位置 (2018):** `src/contexts.cc`、`src/contexts.h`、`src/contexts-inl.h`、`src/field-type.cc`、`src/ast/scopeinfo.cc`
- **现代位置 (2026):** `src/objects/contexts.cc`、`src/objects/contexts.h`、`src/objects/contexts-inl.h`、`src/objects/field-type.cc`、`src/objects/scope-info.cc`
- **冲突原因:** 旧补丁依赖的 `Context::Lookup` 扩展参数、`scopeinfo` symbolic slot helper、旧文件命名与现代对象目录结构都不再一致；同时 `contexts-inl.h` 与 `field-type.cc` 剩余旧 hunk 里混有临时调试改动。

### 2. 逻辑映射 (Mapping)

- **补丁意图:** 把上下文查找和 scope-info 扩展重新映射到现代 `src/objects/` 目录，并明确哪些旧 hunk 只是调试残留、不需要硬移植。
- **适配方案:** 具体到文件如下：
- **文件级处理: `src/objects/contexts.h`**
  新增 `Context::Lookup(...)` 的兼容重载，额外接收 `int* symbolic_index`。
- **文件级处理: `src/objects/contexts.cc`**
  将原有 `Context::Lookup(...)` 接到新重载；在脚本上下文、普通上下文、debug-eval 包装路径中尽量透传 `symbolic_index`；无法兼容时回落为 `Context::kNotFound`。
- **文件级处理: `src/objects/scope-info.h`**
  新增 `VariableLookupResult::taint_symbolic_index`，并补 `ContextLengthWithoutTaint()`、`SymbolicSlotFor(int context_slot)`。
- **文件级处理: `src/objects/scope-info.cc`**
  在 `ContextSlotIndex(...)` 中写入 `taint_symbolic_index`；将 `ContextLengthWithoutTaint()` 实现为 `ContextLength()`；将 `SymbolicSlotFor(...)` 实现为返回原 context slot。
- **文件级处理: `src/objects/contexts-inl.h`**
  已审阅。旧补丁残留内容只有临时调试 include，不构成稳定接口要求，因此不做直接源码改动。
- **文件级处理: `src/objects/field-type.cc`**
  已审阅。旧补丁残留内容为临时 debug 输出，不构成目录搬迁后的功能依赖，因此不做直接源码改动。

### 3. 代码对比 (简述)

| **NDSS 2018 (Old)** | **Modern V8 Adaptation (New)** |
| --- | --- |
| `Context::Lookup(..., int* symbolic_index)` | 在 `src/objects/contexts.h/.cc` 中补兼容重载 |
| `scopeinfo.cc` | 重命名并迁移到 `src/objects/scope-info.cc` |
| `VariableLookupResult` 上的 symbolic 字段 | 在 `src/objects/scope-info.h/.cc` 中补 `taint_symbolic_index` |
| `ContextLengthWithoutTaint()` / `SymbolicSlotFor(...)` | 在 `src/objects/scope-info.h/.cc` 中补 helper |
| `src/contexts-inl.h` 调试 include | 按“已审阅，无需直接改动”关闭 |
| `src/field-type.cc` debug 输出 | 按“已审阅，无需直接改动”关闭 |

### 4. 结论/风险

- **状态:** 已解决
- **风险:** 当前只完成了接口兼容与结构落点兼容，没有恢复旧版真正独立的 symbolic slot 存储语义；如果后续逻辑依赖双槽位 context layout，仍需单独做语义级移植。
