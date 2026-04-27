# V8 Patch 移植记录：misc

### 1. 冲突概况

- **原始位置 (2018):** `src/objects.cc`、`src/objects.h`、`src/objects-inl.h`、`src/flag-definitions.h`、`src/factory.cc`、`src/api.cc`、`src/isolate.cc`、`src/bootstrapper.cc`、`src/uri.cc`、`src/json-parser.cc`、`src/json-stringifier.cc`、`src/x64/macro-assembler-x64.cc`、`src/globals.h`、`src/compiler.cc`、`src/code-stub-assembler.cc`、`src/string-builder.cc`、`src/string-builder.h`、`src/v8.cc`、`src/x64/code-stubs-x64.cc`、`src/ast/scopeinfo.cc`
- **现代位置 (2026):** 这些实现分别落到 `src/objects/`、`src/flags/`、`src/heap/`、`src/api/`、`src/execution/`、`src/init/`、`src/strings/`、`src/json/`、`src/common/`、`src/codegen/`、`src/builtins/`、`src/runtime/` 等目录；其中 `compiler.cc` 的真实现代路径为 `src/codegen/compiler.cc`，`x64` 两项则已发生 successor 迁移。
- **冲突原因:** 这一组文件数量最多、迁移范围最广，而且部分旧文件虽然名字附近还存在，但真实行为承载位置已经变化，不能简单理解为“只要改 include 路径”。

### 2. 逻辑映射 (Mapping)

- **补丁意图:** 处理第五类中最杂、最容易被误判成“只是路径修复”的那批冲突，把旧补丁依赖的 taint / symbolic 挂点重新映射到现代真实承载位置。
- **适配方案:** 具体到文件如下：
- **文件级处理: `src/common/globals.h`**
  补 `tainttracking::FrameType`、`TaintType`、`TaintData`、`kInternalizedStringsEnabled`、`FlattenTaint(...)`、`FlattenTaintData(...)`、`SetTaintStatus(...)`、`GetTaintStatus(...)`、`GetWriteableStringTaintData(...)`、`CheckTaintDebug(...)`、`InstanceCounter` 前置声明。
- **文件级处理: `src/flags/flag-definitions.h`**
  补 `taint_log_file`、`taint_tracking_job_id`、`taint_tracking_enable_header_logging`、`taint_tracking_enable_page_logging`、`taint_tracking_enable_symbolic`。
- **文件级处理: `src/objects/objects.h`**
  补 `Object::ToPrimitive(..., tainttracking::FrameType frame_type)` 兼容参数。
- **文件级处理: `src/objects/objects-inl.h`**
  将 `Object::ToPrimitive(...)` 连接到新的 `frame_type` 兼容参数。
- **文件级处理: `src/objects/js-objects.h`**
  补 `JSReceiver::ToPrimitive(..., tainttracking::FrameType frame_type)` 兼容参数。
- **文件级处理: `src/objects/js-objects.cc`**
  在 exotic-to-primitive 调用路径上透传 `frame_type` 到 `Execution::Call(...)`。
- **文件级处理: `src/objects/objects.cc`**
  将 getter/setter 访问器路径分别接到 `FrameType::kGetterAccessor` 与 `FrameType::kSetterAccessor`；同时把 JS accessor 与 API accessor 两条路径都接住。
- **文件级处理: `src/builtins/builtins.h`**
  为 `Builtins::InvokeApiFunction(...)` 增加 `frame_type` 兼容参数。
- **文件级处理: `src/builtins/builtins-api.cc`**
  实现上述兼容参数版本，当前保持 no-op 语义。
- **文件级处理: `src/strings/string-builder.h`**
  补 taint 形态兼容的 `Append(...)` 与 `AppendCString(...)` 重载外形。
- **文件级处理: `src/strings/string-builder-inl.h`**
  补现代 inl 路径上的对应声明与五参数 `StringBuilderConcatHelper(...)` 声明。
- **文件级处理: `src/strings/string-builder.cc`**
  实现五参数 `StringBuilderConcatHelper(...)` 兼容 shim，并在 `ReplacementStringBuilder::ToString()` 末尾加入 no-op taint debug checkpoint。
- **文件级处理: `src/strings/uri.cc`**
  在 `Decode`、`Encode`、`Escape`、`Unescape` 返回路径补 no-op taint debug checkpoint。
- **文件级处理: `src/json/json-parser.cc`**
  在 internalization 路径接入 `kInternalizedStringsEnabled` 兼容 guard，并统一返回路径 checkpoint。
- **文件级处理: `src/json/json-stringifier.cc`**
  在 fast / slow `JsonStringify(...)` 返回路径补 checkpoint。
- **文件级处理: `src/codegen/compiler.cc`**
  增加 `NotifyTaintTrackingBeforeCompile(...)` no-op 钩子。
- **文件级处理: `src/init/v8.cc`**
  增加 once-per-process no-op init / teardown 钩子。
- **文件级处理: `src/codegen/code-stub-assembler.cc`**
  作为旧 `src/x64/macro-assembler-x64.cc` 字符串分配 hunk 的真实 modern successor，把 `IncrementAndStoreTaintInstanceCounter(...)` 接到顺序字符串和 sliced string 分配 helper。
- **文件级处理: `src/builtins/builtins-string-gen.cc`**
  作为旧 `src/x64/code-stubs-x64.cc` substring 路径的 successor，增加默认关闭的 substring runtime fallback 钩子。
- **文件级处理: `src/runtime/runtime-strings.cc`**
  作为旧 substring 路径 remap 的另一半真实现代承载位置，保留 runtime substring 实现落点。
- **文件级处理: `src/objects/scope-info.h/.cc`**
  作为旧 `scopeinfo.cc` 的重命名 successor，承接相关 symbolic helper；细节另见 `objects_context.md`。

### 3. 代码对比 (简述)

| **NDSS 2018 (Old)** | **Modern V8 Adaptation (New)** |
| --- | --- |
| `src/globals.h` | `src/common/globals.h`，补 taint placeholder / `FrameType` / `InstanceCounter` |
| `src/flag-definitions.h` | `src/flags/flag-definitions.h`，补 taint 相关 flags |
| `src/objects.h` / `src/objects-inl.h` | `src/objects/objects.h` / `src/objects/objects-inl.h`，补 `ToPrimitive(..., FrameType)` |
| `src/api.cc` 相关 accessor 调用 | 在 `src/api/api.cc`、`src/builtins/builtins.h/.cc` 接现代兼容签名 |
| `src/string-builder*` | `src/strings/string-builder*`，补 append / concat helper |
| `src/uri.cc` / `src/json-*` | 在现代路径上补 no-op taint debug checkpoint |
| `src/compiler.cc` | `src/codegen/compiler.cc`，补编译前 no-op 钩子 |
| `src/v8.cc` | `src/init/v8.cc`，补 once-per-process no-op 钩子 |
| `src/x64/macro-assembler-x64.cc` | remap 到 `src/codegen/code-stub-assembler.cc` 的字符串分配 helper |
| `src/x64/code-stubs-x64.cc` | remap 到 `src/builtins/builtins-string-gen.cc` / `src/runtime/runtime-strings.cc` |
| `src/ast/scopeinfo.cc` | `src/objects/scope-info.cc/.h` |

### 4. 结论/风险

- **状态:** 已解决
- **风险:** 这一组虽然已经完成第五类层面的目录与接口修复，但牵涉面最广；后续如果继续恢复 taint/symbolic 语义，新增工作大概率仍会集中在 `objects*`、`string-builder*`、`compiler`、`globals/flags` 以及 `x64 successor` 这几条线上。
