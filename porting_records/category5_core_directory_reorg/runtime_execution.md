# V8 Patch 移植记录：runtime_execution

### 1. 冲突概况

- **原始位置 (2018):** `src/execution.cc`、`src/execution.h`、`src/frames.cc`、`src/frames.h`、`src/isolate.h`、`src/isolate.cc`
- **现代位置 (2026):** `src/execution/execution.cc`、`src/execution/execution.h`、`src/execution/frames.cc`、`src/execution/frames.h`、`src/execution/isolate.h`、`src/execution/isolate.cc`
- **冲突原因:** 路径搬迁后，老补丁依赖的 `FrameType` 参数、taint stack frame 信息接口、`isolate` 上的 taint 数据访问入口，在现代树里都缺失或签名不一致。

### 2. 逻辑映射 (Mapping)

- **补丁意图:** 让旧补丁在执行调用、栈帧日志、`isolate` taint runtime 访问这三条主线上，重新挂到现代 `src/execution/` 目录。
- **适配方案:** 采用“先补兼容接口，再保留现代行为不变”的策略，具体到文件如下：
- **文件级处理: `src/execution/execution.h`**
  新增 `Execution::Call(...)` 和 `Execution::New(...)` 的 `tainttracking::FrameType frame_type` 兼容参数。
- **文件级处理: `src/execution/execution.cc`**
  实现对应兼容参数版本，当前使用 `USE(frame_type)` 保持现代执行逻辑不变。
- **文件级处理: `src/execution/frames.h`**
  新增 `StackFrame::TaintStackFrameInfo` 结构和 `InfoForTaintLog()` 接口声明。
- **文件级处理: `src/execution/frames.cc`**
  实现默认 `InfoForTaintLog()`，并为 `JavaScriptFrame` 返回脚本、位置、行号等现代树里仍可获得的信息。
- **文件级处理: `src/execution/isolate.h`**
  增加 `tainttracking::TaintTracker` 前置声明，补 `taint_tracking_data()` 与 `taint_tracking_data() const` 接口。
- **文件级处理: `src/execution/isolate.cc`**
  将上述两个接口实现为中性 stub，当前统一返回 `nullptr`。

### 3. 代码对比 (简述)

| **NDSS 2018 (Old)** | **Modern V8 Adaptation (New)** |
| --- | --- |
| `Execution::Call(..., FrameType)` | 在 `src/execution/execution.h/.cc` 中补兼容参数 |
| `Execution::New(..., FrameType)` | 在 `src/execution/execution.h/.cc` 中补兼容参数 |
| `StackFrame::InfoForTaintLog()` | 在 `src/execution/frames.h/.cc` 中补兼容接口 |
| `JavaScriptFrame` 输出 taint log 栈帧信息 | 在 `src/execution/frames.cc` 中返回现代脚本位置信息 |
| `isolate->taint_tracking_data()` | 在 `src/execution/isolate.h/.cc` 中补中性 stub |

### 4. 结论/风险

- **状态:** 已解决
- **风险:** 这一组当前解决的是“接口和路径落点”问题，不是完整 taint runtime 恢复；任何后续真正依赖 `taint_tracking_data()` 非空或 `FrameType` 参与执行逻辑的旧补丁，仍需要继续实现现代语义。
