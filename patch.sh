#!/bin/bash

# --- 配置区 ---
# 补丁文件所在的文件夹绝对路径
PATCH_DIR="/Users/yangchengchang/Documents/BUPT/软件分析/论文/Web安全/实验"

# 目标文件列表
TARGETS=(
    # "v8.h"
    ## "TAINT_TRACKING_README"
    ## "taint_tracking-inl.h"
    # "full-codegen-x64.cc"
    # "objects.cc"
    # "runtime.h"
    # "flag-definitions.h"
    # "runtime-internal.cc"
    # "BUILD.gn"
    # "full-codegen.h"
    # "factory.cc"
    # "api.cc"
    # "isolate.cc"
    # "objects.h"
    # "builtins-string.cc"
    # "bootstrapper.cc"
    # "builtins-global.cc"
    ## "taint_log_record.h"
    # "hydrogen.cc"
    # "runtime-strings.cc"
    ## "taint_log_record.cc"
    # "uri.cc"
    # "objects-inl.h"
    # "builtins.h"（上下文没对齐）
    # "json-parser.cc"（找不到）
    # "macro-assembler-x64.cc"（找不到）
    # "globals.h"（找不到）
    # "compiler.cc"（找不到）
    # "code-stub-assembler.cc"（找不到）
    # "string-builder.cc"（找不到）
    # "runtime-regexp.cc"（上下文没对齐）
    # "bytecode-generator.cc"（上下文没对齐）
    # "scopeinfo.cc"（找不到）
    # "heap.cc"（上下文没对齐）
    # "v8.cc"（找不到）
    # "string-builder.h"（找不到）
    # "json-stringifier.cc"（找不到）
    # "builtins-x64.cc"（上下文没对齐）
    # "code-stubs-x64.cc"(找不到)
    # "externalize-string-extension.cc"（上下文没对齐）
    # "parser.cc"(上下文没对齐)
    # "parser.h"（上下文没对齐）
)

echo "开始批量合并补丁..."
echo "当前补丁目录: $PATCH_DIR"
echo "--------------------------------------"

# 进入你的代码仓库根目录 (假设脚本在根目录执行，如果不确定可以手动 cd)
# cd /你的/v8/源码/路径

for FILE in "${TARGETS[@]}"; do
    # 转换逻辑：将 . 替换为 _ 并加上 .txt 
    # 例如 v8.cc -> v8_cc.txt
    PATCH_NAME="${FILE//./_}.txt"
    
    # 完整路径
    FULL_PATCH_PATH="$PATCH_DIR/$PATCH_NAME"

    # 检查补丁文件是否存在
    if [ -f "$FULL_PATCH_PATH" ]; then
        echo ">>> 正在应用补丁: $PATCH_NAME (针对 $FILE)"
        
        # 执行 patch 命令
        # --batch: 自动回答默认选项，不询问
        # --forward: 如果补丁看起来已经应用过了，跳过
        patch -p1 < "$FULL_PATCH_PATH"
        
        if [ $? -eq 0 ]; then
            echo "    [成功]"
        else
            echo "    [失败] 请检查 $FILE 的冲突情况"
        fi
    else
        echo ">>> [跳过] 找不到补丁文件: $FULL_PATCH_PATH"
    fi
done

echo "--------------------------------------"
echo "所有补丁应用尝试完毕。"