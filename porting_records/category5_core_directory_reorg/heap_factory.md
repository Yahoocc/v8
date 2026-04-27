# V8 Patch 移植记录：heap_factory

### 1. 冲突概况

- **原始位置 (2018):** `src/factory.h`，相关旧实现逻辑在 `src/factory.cc`
- **现代位置 (2026):** `src/heap/factory.h`、`src/heap/factory.cc`
- **冲突原因:** `Factory` 从 `src/` 根目录迁入 `src/heap/` 后，旧补丁依赖的 internalized string helper 形态在现代树里没有现成的直接对应入口。

### 2. 逻辑映射 (Mapping)

- **补丁意图:** 让旧补丁中围绕 internalized string 的 helper 调用，能在现代 `src/heap/` 目录下继续有稳定挂点。
- **适配方案:** 具体到文件如下：
- **文件级处理: `src/heap/factory.h`**
  补 `NewOneByteInternalizedSubStringHelper(...)`、`NewInternalizedStringImplHelper(...)` 等 helper 声明。
- **文件级处理: `src/heap/factory.cc`**
  实现上述 helper，并让现代主流程继续通过 helper / 转发路径承接旧调用形态。

### 3. 代码对比 (简述)

| **NDSS 2018 (Old)** | **Modern V8 Adaptation (New)** |
| --- | --- |
| `src/factory.h` | `src/heap/factory.h` |
| `NewOneByteInternalizedSubString(...)` 旧 helper 形态 | 在 `src/heap/factory.h/.cc` 中拆出 `...Helper(...)` |
| `NewInternalizedStringImpl(...)` 旧 helper 形态 | 在 `src/heap/factory.h/.cc` 中拆出 `...ImplHelper(...)` |

### 4. 结论/风险

- **状态:** 已解决
- **风险:** 当前先解决的是 helper 入口兼容，不代表 internalized string 的旧 taint 语义已经完整恢复；如后续要恢复更深层字符串语义，还需要继续下探 `factory.cc` 与 strings 相关路径。
