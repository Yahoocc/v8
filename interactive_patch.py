import re
import collections
import os

# 开启 Windows 终端的 ANSI 颜色支持
if os.name == 'nt':
    os.system('')

def print_human_readable_diff(diff_blocks):
    """将机器读的 diff 转换为人类易读的彩色说明书格式"""
    for block in diff_blocks:
        lines = block.split('\n')
        for line in lines:
            if not line:
                continue
                
            # 跳过无用的 git 文件头信息
            if line.startswith(('diff --git', 'index ', '--- a/', '+++ b/')):
                continue
            
            # 解析行号标记 (例如 @@ -37,6 +37,7 @@ void AddAndSetEntry...)
            if line.startswith('@@'):
                match = re.search(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)', line)
                if match:
                    line_num = match.group(1)
                    func_context = match.group(3).strip()
                    print(f"\n\033[1;36m📍 定位到文件大约 第 {line_num} 行附近\033[0m", end="")
                    if func_context:
                        print(f"\033[1;36m (参考范围: {func_context})\033[0m")
                    else:
                        print()
                    print("\033[90m" + "-"*50 + "\033[0m")
                else:
                    print(f"\n\033[1;36m📍 {line}\033[0m")
                    
            # 解析删除的代码 (-) -> 红色
            elif line.startswith('-'):
                print(f"\033[1;31m❌ 删除当前行 : {line[1:]}\033[0m")
                
            # 解析新增的代码 (+) -> 绿色
            elif line.startswith('+'):
                print(f"\033[1;32m✅ 新增一行代码: {line[1:]}\033[0m")
                
            # 解析上下文代码 (空格开头) -> 灰色/暗色，保持对齐
            elif line.startswith(' '):
                print(f"\033[0m   上下文参考  : {line[1:]}\033[0m")
                
            # 兼容其他特殊情况（如 \ No newline at end of file）
            elif line.startswith('\\'):
                continue
            else:
                print(line)

def main():
    stat_file = 'v8_patch_statistic.txt'
    patch_file = 'v8_patch.txt'

    if not os.path.exists(stat_file) or not os.path.exists(patch_file):
        print(f"错误：请确保 {stat_file} 和 {patch_file} 都在当前目录下。")
        return

    # 1. 获取逆序文件列表
    file_paths = []
    with open(stat_file, 'r', encoding='utf-8') as f:
        for line in f:
            match = re.search(r'\|\s*\d+\s*\|\s*([^|]+?)\s*\|', line)
            if match:
                path = match.group(1).strip()
                if path != "文件路径":
                    file_paths.append(path)
    file_paths.reverse()

    # 2. 解析完整补丁
    print("正在解析并翻译 Patch 文件，请稍候...")
    patches = collections.defaultdict(list)
    current_file = None
    current_diff = []

    with open(patch_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if line.startswith('diff --git'):
                if current_file and current_diff:
                    patches[current_file].append("\n".join(current_diff))
                file_match = re.search(r' b/(.*)', line)
                if file_match:
                    current_file = file_match.group(1).strip()
                current_diff = [line]
            else:
                if current_file:
                    current_diff.append(line)
        
        if current_file and current_diff:
            patches[current_file].append("\n".join(current_diff))

    # 3. 交互式修改
    total_files = len([p for p in file_paths if p in patches])
    current_index = 1

    for path in file_paths:
        if path in patches:
            os.system('cls' if os.name == 'nt' else 'clear') 
            
            print(f"\033[1;33m进度: [{current_index}/{total_files}]\033[0m")
            print(f"\033[1;35m【当前需要修改的文件】: {path}\033[0m")
            print("==================================================")
            
            # 使用新的易读打印函数
            print_human_readable_diff(patches[path])
            
            print("\n==================================================")
            user_input = input(f"\n👉 文件 {path} 修改完毕了吗？\n(按【回车键】继续下一个，输入 'q' 退出): ")
            
            if user_input.strip().lower() == 'q':
                print("已中断修改流程。")
                break
                
            current_index += 1

    if current_index > total_files:
        print("🎉 恭喜！所有文件的修改都已完成！")

if __name__ == "__main__":
    main()