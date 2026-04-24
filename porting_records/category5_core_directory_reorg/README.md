# 第五类：核心目录大重构移植记录总纲

这组文档专门记录“第五类：核心目录大重构（文件还在，但搬家了）”的移植处理结果。

这一类问题的本质，不是某段逻辑彻底消失了，而是：

- 旧补丁针对的是 2018 年前后的 V8 目录结构
- 现代 V8 把大量 `src/` 根目录文件重新归类到了子目录
- 有些文件虽然名字还在，但真正承载旧逻辑的现代实现位置已经变了
- 有些旧 hunk 看起来像功能改动，实际只是临时调试输出或阶段性改动，不应该机械照搬

因此，第五类的工作重点不是“把旧路径修回去”，而是：

1. 找到现代 V8 中真实的实现落点
2. 判断旧 hunk 属于哪一类问题
3. 在现代路径上补兼容接口、兼容签名或中性 hook
4. 对已经被现代架构吸收的旧文件做 successor remap
5. 对不值得前移的临时调试型旧 hunk 明确标记为“已审阅，无需直接改动”

## 整体修改思路

本轮对第五类问题采取的是“先解决目录与接口冲突，再保留语义扩展空间”的策略。

### 1. 先解决文件搬家问题

第一步不是急着恢复 taint runtime 的所有旧逻辑，而是先把旧补丁依赖的文件和接口重新挂到现代目录结构下。

典型例子包括：

- `src/execution.cc` -> `src/execution/execution.cc`
- `src/contexts.h` -> `src/objects/contexts.h`
- `src/factory.h` -> `src/heap/factory.h`
- `src/bootstrapper.h` -> `src/init/bootstrapper.h`
- `src/uri.cc` -> `src/strings/uri.cc`
- `src/json-parser.cc` -> `src/json/json-parser.cc`
- `src/globals.h` -> `src/common/globals.h`

### 2. 再解决旧签名与现代接口不匹配的问题

很多冲突并不是文件找不到，而是老补丁调用的函数签名已经和现代 V8 不一致。

这类情况的处理方法是：

- 在现代文件上补一个兼容重载
- 或者在现代实现上增加旧参数形态
- 但默认不改变现代 V8 原有主逻辑

比如：

- `Execution::Call(..., FrameType)`
- `Execution::New(..., FrameType)`
- `Object::ToPrimitive(..., FrameType)`
- `JSReceiver::ToPrimitive(..., FrameType)`
- `Builtins::InvokeApiFunction(..., frame_type)`
- `Context::Lookup(..., int* symbolic_index)`

### 3. 对没有真实现代位置的旧文件做 remap

有一部分旧文件虽然曾经存在，但在现代树里已经不再是最合适的承载位置。

这类问题如果继续死盯原文件名，就会误判成“还没改完”。

本轮已经明确处理过的典型 remap 有：

- 旧 `src/assembler.h/.cc`
  现代真实落点应看 `src/codegen/external-reference.h/.cc`

- 旧 `src/x64/macro-assembler-x64.cc` 中那批字符串分配 taint hunk
  现代更合理的 successor 是
  `src/codegen/code-stub-assembler.cc`
  中的字符串分配 helper

- 旧 `src/x64/code-stubs-x64.cc` 的 substring 路径
  现代真实落点是
  `src/builtins/builtins-string-gen.cc`
  和
  `src/runtime/runtime-strings.cc`

### 4. 对“只剩调试意义”的旧 hunk 不强行前移

有些旧补丁 diff 里残留的是：

- 临时 `#include <iostream>`
- 临时 `std::cerr`
- 调试打印
- 某个阶段为了排查问题加入的过渡性代码

这些内容不构成现代 V8 稳定接口需求。

这一类本轮统一按以下原则处理：

- 认真审阅
- 在对应记录里明确写明“已审阅，无需直接改动”
- 不为了“看起来每个文件都动过”而做无意义修改

## 已经完成的工作

如果从第五类的目标来看，本轮已经完成的是：

- 第五类涉及的旧文件，已经全部找到现代路径或现代 successor
- 旧补丁常用的关键签名冲突，已经补上现代兼容入口
- 目录重构带来的 rebase / cherry-pick 冲突，已经不再属于“未处理状态”

如果从更大的 taint runtime 目标来看，本轮**没有**声称完成的是：

- 完整恢复旧 NDSS taint runtime
- 恢复所有 symbolic / logging / propagation 真实语义
- 保证运行时行为已经与旧版一致

## 各文档记录说明

下面这几份文件是按“现代归属目录”分组整理的主记录。

### `runtime_execution.md`

记录运行时与执行路径相关的迁移，主要包括：

- `execution.h/.cc`
- `frames.h/.cc`
- `isolate.h/.cc`

适合查看：

- `FrameType` 参数怎么接住的
- taint stack frame 信息接口补在了哪里
- `taint_tracking_data()` 为什么现在只是 stub

### `objects_context.md`

记录对象、上下文、scope-info 相关迁移，主要包括：

- `contexts.h/.cc`
- `contexts-inl.h`
- `field-type.cc`
- `scope-info.h/.cc`

适合查看：

- `Context::Lookup(..., symbolic_index)` 是怎么兼容的
- `scopeinfo.cc` 改名到 `scope-info.cc` 后怎么落地的
- 为什么 `contexts-inl.h` 和 `field-type.cc` 被判定为“已审阅，无需直接改动”

### `codegen_assembler.md`

记录 codegen / CSA / external reference 相关迁移，主要包括：

- `source-position-table.h/.cc`
- `code-stub-assembler.h/.cc`
- `external-reference-table.h/.cc`
- `external-reference.h/.cc`

适合查看：

- AST taint index 相关接口是如何中性兼容的
- `IncrementAndStoreTaintInstanceCounter(...)` 接到了哪里
- 旧 `assembler.h/.cc` 为什么要 remap 到 `external-reference.h/.cc`

### `api_init.md`

记录 API 与初始化辅助路径相关迁移，主要包括：

- `api-arguments.cc`
- `api-arguments-inl.h`
- `bootstrapper.h/.cc`

适合查看：

- 为什么 `api-arguments.cc` 本身没有大改
- 为什么真实落点要看 `api-arguments-inl.h`
- `SimpleInstallFunction(...)` 旧签名兼容是怎么补的

### `heap_factory.md`

记录 `Factory` 相关搬迁，主要包括：

- `factory.h`
- `factory.cc`

适合查看：

- `factory` 从 `src/` 根目录迁到 `src/heap/` 后如何接旧 helper
- `NewOneByteInternalizedSubStringHelper(...)`
- `NewInternalizedStringImplHelper(...)`

### `misc.md`

这是第五类里最杂、也最重要的一份补充记录，主要收敛那些跨目录、跨模块、需要 remap 才能讲清楚的项，包括：

- `objects*`
- `flag-definitions.h`
- `globals.h`
- `api.cc`
- `uri.cc`
- `json-*`
- `compiler.cc`
- `v8.cc`
- `string-builder*`
- `x64` 两条 successor remap
- `scope-info` 在这一组中的关联补充

适合查看：

- 旧 `objects` 路径上的 taint 接口到底补在了哪些现代文件
- `globals.h` 和 `flag-definitions.h` 为什么属于第五类的基础兼容层
- `x64` 那两项为什么不能按旧文件名继续硬改

## 推荐阅读顺序

如果你是第一次接手第五类，建议按下面顺序读：

1. 先看 `README.md`
   明确整体策略、完成边界、各文件分工
2. 再看 `runtime_execution.md`
   先建立对“现代兼容签名”处理方式的直觉
3. 再看 `objects_context.md`
   了解 `Context` / `ScopeInfo` 这类结构迁移怎么处理
4. 再看 `codegen_assembler.md`
   了解 codegen 与 successor remap 的处理方式
5. 最后看 `misc.md`
   处理最杂、最容易误判的那些跨模块 remap

## 文档使用注意事项

### 1. 不要把“已解决”理解成“语义完全恢复”

这里写的“已解决”，是指第五类目录搬家冲突已经解决。

不是说：

- 老 taint runtime 已经完整回来了
- 所有旧行为都 1:1 恢复了
- 现在已经可以把第五类以外的语义问题也视为完成

### 2. 不要只按旧文件名判断是否漏改

第五类里最容易误判的，就是：

- 旧文件名还记得
- 但现代真实行为位置已经换了

所以后续核对时要优先看“现代真实落点”，而不是只看旧文件名本身。

### 3. 这组记录的目标是帮助后续继续往前走

这组文档不仅是“本轮改了什么”的记录，也是在给后续继续移植的人降低成本。

它的价值在于把下面这些事情提前说清楚：

- 哪些文件已经处理完
- 哪些修改是兼容层
- 哪些是 no-op hook
- 哪些是 successor remap
- 哪些不用再反复怀疑是不是漏了

## 当前结论

第五类现在可以从“待解决冲突类型”里移出。

从这里往后，如果继续推进工作，重点就不再是“文件搬家了怎么办”，而是：

- taint runtime 真实对象和生命周期
- symbolic 数据结构与传播语义
- logging / sink / source 相关现代实现
- 编译、运行、测试层面的行为验证

也就是说，后续工作已经从“目录重构冲突修复”进入“语义恢复与验证”阶段。
