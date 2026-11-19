# mtree 读取的根目录约束（内容根目录边界）

- 代码基线：`4a5944b`（`task/188`，libarchive 主分支）
- 主体文件：`libarchive/archive_read_support_format_mtree.c`
- 构建方式：本机无 autotools/flex/bison，使用手写 `config.h` + `gcc` 直接编译
  （zlib 可用；无 liblzma/bz2/zstd，相关用例按环境跳过或在基线即失败）。
  构建与验证脚本在 `/srv/fb2/mei8085/0188-lab/`。

## 0. 结论摘要

题面要求“mtree 清单驱动的归档读取必须被限制在内容根目录内”。实现方式是给
mtree 读取器增加统一的**词法规范化 + 根内包含检查**，并在读取头、链接目标、
`contents` 目标、重复行与 `checkfs` 回读文件系统的所有路径上复用同一套规则。

| 要求 | 实现 |
|---|---|
| 相对路径、`..`、绝对路径、符号链接目标、重复条目遵守同一边界 | 所有名字最终都走 `mtree_canonicalize()` + `mtree_resolve_path()` + `mtree_check_entry()` |
| 越界条目被拒绝且保留可诊断错误 | 每类越界设置独立错误文本，返回 `ARCHIVE_FAILED`，可继续读下一条 |
| 合法目录/文件/权限/时间元数据按清单生成 | 合法条目的 pathname/filetype/mode/uid/gid/mtime(含纳秒)/size/symlink 全部按清单输出 |
| 空根目录与非规范分隔符不能绕过边界 | `root=` 置空或 `!root` 只恢复默认边界而非关闭检查；`//`、`/./`、`/../` 先折叠再判定 |
| 一份清单失败后，下一份从干净上下文开始 | 失败即 `mtree_reset_manifest()` 并粘滞 `ARCHIVE_FATAL`；新读取器从空上下文解析 |

## 1. 边界模型

- **内容根目录（content root）**：可读命名空间。
  - 未配置 `root` 时，边界是起始目录（`.`），且**始终存在**；`..` 不能越过它。
  - 配置 `root=<dir>` 时，边界是该目录。
  - `root=`（空值）与 `mtree:!root` 都只是“清除配置的根、回到默认边界”，
    不会关闭检查 —— 见 `mtree_set_root()`。
  - `root` 既用于锚定绝对清单路径，也在 `checkfs` 时锚定实际回读的文件。
- **规范化**：`mtree_canonicalize()` 按 `/` 分量折叠，处理重复分隔符、`.`、
  连续 `..`；相对路径中越顶的 `..` 置 `escaped` 并返回失败；绝对路径中的
  `..` 在 `/` 处夹紧（与内核一致）。
- **绝对名**：仅当 `root` 本身是绝对路径且该名词法上位于 `root` 之下时才接受；
  否则拒绝。
- **符号链接目标**：相对目标按“链接所在目录”解析，同样受根约束；
  绝对目标遵循绝对名规则。
- **`contents` 目标**：按内容根解析（不是按条目所在目录），同样受根约束。
- **`checkfs` 回读**：路径由 `mtree_fs_path()` 用配置根拼接；对会被 `open()`
  跟随的普通文件/目录，再用 `realpath()` 二次确认（`HAVE_REALPATH` 可用时），
  防止**被攻击的磁盘树**里的符号链接把回读导向根外。声明为 `link` 的条目
  只做 `lstat()`，不会被跟随。

## 2. 每一类越界的错误与返回值

| 情况 | 返回 | 诊断示例 |
|---|---|---|
| 相对名越顶（`a/../../x`） | `ARCHIVE_FAILED` | `Pathname "a/../../x" is outside the content root` |
| 顶层裸 `..`（无打开的根目录） | `ARCHIVE_FAILED` | `Pathname ".." is outside the content root` |
| 非规范分隔符（`a//..//..//x`） | `ARCHIVE_FAILED` | 同上 |
| 绝对名且根非绝对/不含它 | `ARCHIVE_FAILED` | `Pathname "/etc/passwd" is outside the content root` |
| 符号链接目标越界 | `ARCHIVE_FAILED` | `Symbolic link target "..." is outside the content root` |
| `contents` 越界 | `ARCHIVE_FAILED` | `Contents path "..." is outside the content root` |
| 磁盘树符号链接越界（`checkfs`） | `ARCHIVE_FAILED` | `Contents path "..." resolves outside the content root` |
| 名称含转义 NUL | `ARCHIVE_FAILED` | `Pathname contains an embedded NUL character` |
| 清单语法错误 | `ARCHIVE_FATAL` 且粘滞 | `Can't parse line N` |

每次拒绝后 `this_entry` 前进到下一条，`current_dir` 回卷到本条处理前，
因此**越界条目不会污染后续条目的解析上下文**。

## 3. 兼容性

- mtree 写出器（`mtree` 与 `mtree-classic`）会在末尾用 `..` 关闭它以 `.`
  打开的根目录。该“关闭型 `..`”会回到根而非离开根，因此被识别并放行
  （`root_dir_open` 状态），保证 `archive_read` 能读回 libarchive 自己写出的清单。
- 未配置 `root` 时，合法的相对/完整路径读取行为与之前一致；
  新增的拒绝只针对**真正越出起始目录**的条目。
- `checkfs` 仅在显式开启时才会触发磁盘回读相关的边界检查。

## 4. 验证

- 新增 `libarchive/test/test_read_format_mtree_root.c`（16 个用例）覆盖：
  合法元数据、`..` 越界、相对越界、分隔符越界、绝对名、符号链接目标、
  重复条目、空根选项、失败后上下文重置、转义越界、嵌入 NUL（名字与链接目标）、
  空清单、`checkfs` 磁盘根与磁盘符号链接、失败不泄漏状态、拒绝后保持上下文。
- 现有全部 mtree 用例通过。
- 全量 `libarchive.test` 套件除**基线即失败**的
  `test_read_format_zip_lzma_alone_large_size`（本机无 liblzma）外无回归。
