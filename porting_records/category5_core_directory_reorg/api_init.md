# V8 Patch 移植记录：api_init

### 1. 冲突概况

- **原始位置 (2018):** `src/api-arguments.cc`、`src/bootstrapper.h`
- **现代位置 (2026):** `src/api/api-arguments.cc`、`src/api/api-arguments-inl.h`、`src/init/bootstrapper.h`、`src/init/bootstrapper.cc`
- **冲突原因:** `bootstrapper` 已迁入 `src/init/` 且签名变化；`api-arguments` 的现代 callback 执行逻辑已大量转移到 `api-arguments-inl.h`，不再完全由 `.cc` 文件承载。

### 2. 逻辑映射 (Mapping)

- **补丁意图:** 保留旧补丁在 API callback 与 bootstrap 初始化路径上的可落地接口。
- **适配方案:** 具体到文件如下：
- **文件级处理: `src/init/bootstrapper.h`**
  补 `SimpleInstallFunction(...)` 的旧签名兼容重载。
- **文件级处理: `src/init/bootstrapper.cc`**
  将旧签名重载转发到现代带 `kAdapt` 的实现版本。
- **文件级处理: `src/api/api-arguments-inl.h`**
  在真实 callback 执行路径中加入 `SymbolicMatchesFunctionArgs(...)` 兼容检查。
- **文件级处理: `src/api/api-arguments.cc`**
  已审阅。现代树中该文件主要负责遍历/GC 相关逻辑，不再承载 callback 核心执行行为，因此不强行把已迁移出去的逻辑塞回 `.cc`。

### 3. 代码对比 (简述)

| **NDSS 2018 (Old)** | **Modern V8 Adaptation (New)** |
| --- | --- |
| `src/bootstrapper.h` 旧 `SimpleInstallFunction(...)` | 在 `src/init/bootstrapper.h/.cc` 中补重载并转发 |
| `src/api-arguments.cc` 上的 callback 参数检查 | 落到 `src/api/api-arguments-inl.h` 的真实执行路径 |
| `FunctionCallbackArguments` 的旧 symbolic 参数假设 | 通过 `SymbolicMatchesFunctionArgs(...)` 兼容接口接住 |

### 4. 结论/风险

- **状态:** 已解决
- **风险:** `api-arguments.cc` 这一项的 closure 方式是“行为迁移到现代 inl 实现位置”；如果后续有人只按旧 `.cc` 文件核对，而不看 `api-arguments-inl.h`，容易误判成漏改。
