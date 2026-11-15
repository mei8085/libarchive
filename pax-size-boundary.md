# PAX 扩展记录尺寸/边界安全排查报告

- 被测对象：libarchive（当前工作树 `task/70`，提交 `4a5944b`）中的 tar/PAX 读取器
  `libarchive/archive_read_support_format_tar.c`（3899 行）
- 构建：本地 Debug 构建（`work/build`）与 ASan+UBSan 插桩构建（`work/build-asan`），均未使用容器
- 差分实现：GNU tar 1.35（`/usr/bin/tar`）、Python 3.12 标准库 `tarfile`
- 样本/脚本：`work/samples/`（31 个手工构造样本）、`work/scripts/`（生成器与测试桩）、原始差分输出 `work/differential_runs.txt`、字节布局 `work/layouts.txt`
- 测试桩 `work/scripts/tar_harness.c`：以内存方式喂入文件，逐步打印
  `archive_read_next_header` / `archive_read_data_block` 的返回码、`archive_filter_bytes`
  报告的真实消费位置、条目名/尺寸与实际交付的 body 字节数

---

## 1. 结论摘要

| 编号 | 结论 | 性质 |
|---|---|---|
| F1 | PAX 记录长度字段被静默截断解析（`4abc`→`4`），非法数字无任何告警即覆盖 ustar 尺寸（s14/s31） | **安全缺陷（静默错误输入接受）** |
| F2 | PAX `size` 与 ustar `size` 跨越不同 512 字节块边界时，物理消费完全由 pax 值驱动，可令数据区被重解释为新条目（s22，"隐藏条目"反向出现为"伪造条目"） | 规格未禁止的跨实现共有行为，非本实现独有缺陷 |
| F3 | 同一 pax body 内一条记录畸形 → 整个 body 作废、已成功解析的属性被整体丢弃（s16/s17），与 GNU tar 的"逐条隔离"不同 | 容错策略差异（偏严格，非内存安全问题） |
| F4 | `g` 全局头中出现本实现不支持的按条目属性时直接 FATAL（s20），GNU tar/Python 把它当默认值应用 | 与 POSIX 默认值语义的兼容性差异 |
| — | 全部 31 个样本在 ASan/UBSan 下 **0 起内存越界/未定义行为**；畸形记录的错误路径均能跳过整个 `ext_size+padding`，未发现越界读取 | 未发现内存破坏 |
| — | 越界数值（s04/s05/s27/s28）、截断流（s10）、超大扩展体（s25）均以 FATAL/WARN 终止，**错误后不交付伪有效条目** | 防线有效 |

总体：没有可复现的堆/栈越界或 UB；核心问题集中在 **F1 静默接受非法数值** 与
**F2 尺寸冲突时的块边界语义**。下文给出每个样本的字节布局、真实消费位置、三实现返回结果，
并区分"格式允许的覆盖"与"安全缺陷"。

---

## 2. 关键代码路径（排查依据）

### 2.1 PAX 记录解析 `header_pax_records()`（tar.c:1955-2261）

1. 扩展体尺寸来自 `x`/`g` 头的 ustar size 字段：`ext_size = tar_atol(header->size, ...)`（1991）。
   - `ext_size > entry_limit`(2^60−1) 或 `< 0` 或 `== 0` → `ARCHIVE_FATAL`（1992-2006）。
   - `ext_size > 1 GiB` → 调 `__archive_read_consume(ext_size+padding)` 整体跳过后返回
     `ARCHIVE_WARN`（2009-2018），**不按记录内容分配内存**。
2. 循环内每次最多 `__archive_read_ahead(min(512, ext_size))`（2027-2031），所有读取都被
   `ext_size` 钳制（2038-2040），因此解析器自身不会越过扩展体末尾做前向越界读。
3. 记录长度 `line_length` 为十进制累加（2043-2072），上限 `max_parsed_line_length = 99 999 999`，
   超限返回 WARN；随后校验 `(int64_t)line_length > ext_size`（2074），超出则 WARN。
4. 任意畸形分支都执行 `*unconsumed += ext_size + ext_padding` 后返回（如 2049/2059/2068/2078…），
   即**一次性丢弃整个扩展体及其填充**，块边界因此保持对齐——这是未出现错位读取的根本原因。
5. `value_length = line_length - (p - attr_start)`（2111）。由于进入此处前已保证
   `p < attr_start + line_length`（2083-2084 的空名检查），该减法不会下溢；s18 专门验证了该点，
   UBSan 无报告。
6. 记录结尾必须是 `\n`，否则 WARN 并丢弃剩余扩展体（2169-2174）。

### 2.2 尺寸调和 `header_common()`（tar.c:1382-1436）

- 若存在 pax `size`（`TAR_SIZE_PAX_SIZE` 置位），则 `disk_size` 与
  `entry_bytes_remaining` **都**取 `tar->pax_size`（1395-1396、1420-1421），ustar 头中的
  size 字段被完全忽略；否则才用 `tar_atol(header->size,...)`。
- 两个值分别做 `< 0` 与 `> entry_limit` 检查，失败即 FATAL（1402-1435）。
- 填充 `entry_padding = 0x1ff & (-entry_bytes_remaining)`（1942、2259），即物理块对齐也由
  pax 值决定。**这是 F2 的代码根源**：pax 值同时决定逻辑尺寸、读取字节数与块填充。

### 2.3 pax 数字解析 `pax_attribute_read_number()`（tar.c:2426-2457）→ `tar_atol_base_n()`（3605-3640）

- `tar_atol_base_n` 遇到非进制字符即 `break` 并返回**已累计的部分值**，不报告"未消费完"。
- `pax_attribute_read_number` 仅在结果 `< 0` 或 `== INT64_MAX` 时降级为 WARN；
  对 `"4abc"` 这类尾部垃圾，返回 `ARCHIVE_OK` 且 `result=4`。**这是 F1 的代码根源。**

---

## 3. 格式允许的覆盖规则 vs 安全缺陷（判定标准）

POSIX.1-2008（pax 扩展头，`x`/`g`）规定：

- 扩展记录格式 `"%d %s=%s\n"`，长度字段覆盖**整条记录**（含长度字段自身与结尾 `\n`）。
- `size`、`path`、`uid` 等关键字用于**覆盖**随后常规 ustar 头中的同名字段；因此
  "pax size 与 ustar size 不同"本身是**合法且预期**的（典型用途：文件超过 ustar 八进制
  8 GiB 限制，见 s26/GNU 9 GiB 稀疏归档验证）。
- 长度字段必须与真实记录字节数自洽；数值字段必须是合法十进制整数。对**畸形**输入，
  标准把诊断/恢复策略留给实现。

判定口径：

- **格式允许**：自洽记录对 ustar 字段的覆盖（s06/s07/s13/s15/s26），即使两尺寸不同，
  只要 pax 记录本身合法、消费位置仍落在正确的 512 边界上。
- **安全缺陷**：解析器在输入违反记录自洽性/数值合法性时，(a) 不发出任何错误信号，
  (b) 用解析出的可疑值驱动后续内存/流消费或条目语义（F1）；或 (c) 错误后仍返回可用条目。
- **共有架构行为（非本实现独有）**：F2 在 GNU tar 与 Python tarfile 上可复现完全相同的
  块重解释结果，属于"pax 覆盖块边界"这一规格灰区，而非 libarchive 的实现 bug。

---

## 4. 逐样本字节布局、消费位置与差分结果

位置单位为字节；"消费位置"来自测试桩 `archive_filter_bytes(a,-1)`。
完整原始记录见 `work/differential_runs.txt`，自动布局见 `work/layouts.txt`。

### 4.1 长度错配类（s01、s02、s03、s08、s09、s18）

| 样本 | 扩展体真实字节（偏移 512 起） | 畸形点 | libarchive 结果与消费 | GNU tar | Python tarfile |
|---|---|---|---|---|---|
| s01 | `14 path=AAAAAAAAAAA\n`（真实 20B，谎称 14） | 记录短报 | next_header **WARN**「Malformed pax attributes」；pos 0→1536（整个 512 头+512 体被跳过），随后 `real_file.txt` 正常，body 5B，最终消费 3072/3072 | rc=2「missing newline」，仍解出 real_file.txt | ReadError `invalid header`（拒绝整个归档） |
| s02 | `60 path=BBBBBBBB\n`（真实 17B，谎称 60） | 记录长报，60>ext 剩余 17 | WARN「60 > 17」，pos→1536 对齐，`after_pax.txt` 正常 | rc=2「length 60 out of range」，仍解出 | ReadError |
| s03 | `100000000 path=x\n`（体仅 512B） | 单行长度 > 99 999 999 | WARN「size > 99999999」，无大分配，pos→1536 | rc=2「out of range」 | ReadError |
| s08 | r1 谎称 40（真实 22）+ r2 合法 | 长报吞掉第二条记录区域 | WARN「40 > 28」，整个 body 作废，`entry.txt` 仅按 ustar 解出 | rc=2，仍解出 entry.txt | ReadError |
| s09 | `10 =\n`（真实 5B） | 空名/长报 | WARN「10 > 5」，pos→1536 对齐 | rc=2，仍解出 x.txt | ReadError |
| s18 | `72 path=zzz\n`（真实 12B） | 逼近 value_length 下溢 | WARN「72 > 12」；UBSan 无下溢报告，pos→1536 | rc=2 | ReadError |

要点：长度错配**不会**让 libarchive 错读后续条目边界——所有畸形路径都把
`ext_size+ext_padding` 整体计入 `unconsumed`，下一条目头部始终回到 512 边界。
Python 最严格（直接拒绝），GNU tar 与 libarchive 都能恢复但 GNU 保留逐条诊断。

### 4.2 数值越界类（s04、s05、s27、s28、s31）

| 样本 | pax size 记录 | libarchive | GNU tar | Python |
|---|---|---|---|---|
| s04 | `size=9999999999999999999`（≈1e19 > 2^60） | **FATAL**「Tar size attribute overflow」，pos 0→1024，无条目交付 | rc=2 仍列出 huge.txt(size 0) | 接受 size=1e19，读数据时 OverflowError |
| s05 | `size=-5` | **FATAL**（同上），无条目 | rc=2 列出 neg.txt(0) | 静默忽略该属性，归档可继续 |
| s27 | `size=2^60`（恰为 entry_limit+1） | **FATAL**「Tar entry size overflow」 | — | — |
| s28 | `size=2^60+1` | **FATAL** 同上 | — | — |
| s31 | `size=4abc`，对应 ustar size=9 | **OK，无任何告警**，条目尺寸变成 4，仅交付 4/9 字节（**F1**） | rc=2「invalid size=4abc」，按 ustar 9 写出 9 字节 | 该属性失效，条目 size=0 |

s04/s05 证明：真正的数值越界走的是 FATAL 且不返回条目，防线有效。
s31 是唯一"非法输入被当合法值静默采纳"的路径（详见第 6 节 F1）。

### 4.3 尺寸冲突 / 块边界类（s06、s07、s13、s15、s22、s23、s24、s29）

| 样本 | ustar size | pax size | 物理布局 | libarchive 消费与结果 | GNU/Python |
|---|---|---|---|---|---|
| s06 | 3 | 8 | 8B 数据+504 填充，后接 second.txt | OK，交付 8B，pos 1536→2048，second.txt 边界正确 | 三实现一致（合法覆盖） |
| s07 | 8 | 3 | 8B 数据+504 填充 | OK，交付 3B，仍跳到 2048（按 pax=3 重算填充后恰与 512 边界重合） | 三实现一致 |
| s13 | 3 | 3 然后 9（重复 size） | 9B 数据 | OK，**后者生效** size=9，交付 9B | 三实现一致（POSIX：后值覆盖） |
| s15 | 0 | 512 | carrier 的数据区藏了一个完整伪造 ustar 头 | OK，伪造头作为 1024B 数据被 carrier 吃掉，**未**浮现为条目；legit_after 正常 | 三实现一致（隐藏失败=安全） |
| s22 | 513 | 0 | 物理体 1024B，其首 512B 是带合法校验和的 `forged_spurious.txt` 头 | carrier 尺寸变 **0**、0 字节数据；pos 停在 1536，随后**把数据区首块当新头**，解出伪造条目（4B），再解出 tail_real | **三实现完全相同**：均列出 carrier(0)/forged(4)/tail(2) |
| s23 | 0 | 1024 | 后 1024B 是真实 hidden 条目 | swallower 尺寸 1024，把真实条目当数据吞掉（隐藏），after 正常 | 三实现一致 |
| s24 | 512 | 1 | 512B 区内嵌伪造头 | mild_carrier size=1，交付 1B；伪造头所在块被跳过，mild_tail 正常 | 三实现一致 |
| s29 | 513 | 0 | 同 s22 但伪造头**校验和被破坏** | carrier(0) 后遇到坏头 → **RETRY** 两次逐块重同步，最终只交付 tail.txt；伪造条目被校验和拦截 | GNU「Skipping to next header」；Python 仅列出 carrier |

s22 的精确字节布局（`xxd` 复核）：

```
+0      x 头 PaxHeader（ustar size=含 "11 size=0\n" 的扩展体）
+512    扩展体（"11 size=0\n" + NUL 填充）
+1024   carrier.txt 常规头，ustar size 字段 = 01001(八进制)=513
+1536   物理数据区第 1 块：forged_spurious.txt 的合法 ustar 头（name@+0x600, magic "ustar\0"）
+2048   物理数据区第 2 块（1 字节真实数据 + 填充）
+2560   tail_real.txt 头
...
```

libarchive 在 +1536 处理完 carrier（pax size=0 → 不消费数据），下一次
`next_header` 直接在 +1536 读到伪造头并通过校验和检查，于是产生一个
**语义上不存在于作者意图中、但字节流自洽的条目**。s29 证明这不是无条件的：
破坏校验和后，`checksum()`（tar.c:809）拒绝该块并进入 RETRY 重同步，伪造条目无法落地。

### 4.4 流截断 / 资源类（s10、s11、s25）

| 样本 | 情形 | libarchive | GNU | Python |
|---|---|---|---|---|
| s10 | x 头声称 512B 体，流在 100B 处 EOF | **FATAL**「Truncated ... reading pax attribute name」，pos=512，无条目 | rc=2 Unexpected EOF，无文件 | ReadError empty header |
| s11 | x 头 size=2GiB，文件无头体 | FATAL「Truncated input file」（consume 无法满足），无大分配 | rc=2 EOF | ReadError |
| s25 | 稀疏文件，x 头真实声明 2GiB（>1GiB  sanity 限制），尾端藏真实条目 | WARN「Ignoring oversized pax extensions: 2147483648 > 1073741824」，一次性 consume 2GiB（稀疏 seek），pos 跳到 2147484672 后正确解出 after_big.txt；实测磁盘占用 8KiB | rc=0 正常解出 | 正常解出 |

s25 说明超大扩展体路径是"跳过+告警"而非分配内存，无资源耗尽；且跳过后边界仍精确对齐。

### 4.5 全局头与其他（s20、s21、s30）

- s20：`g` 头内含 `path`（libarchive 不支持的全局按条目属性）→ **FATAL**
  「Unsupported pax global extended header attribute 'path'」；GNU/Python 把它当默认值应用并解出条目。
- s21：`g` 头仅含厂商自定义 `VENDOR.thing` → 正常 OK（在白名单之外被忽略）。
- s30：常规头 size 字段用 base-256 编码 0、pax 覆盖为 4 → libarchive 正常；GNU 报
  「base-256 value out of off_t range」（对家更严格的一个反向差异）。

---

## 5. "错误后是否交付伪有效条目"专项结论

| 错误类别 | 返回码 | 是否仍返回可用条目 | 评价 |
|---|---|---|---|
| 记录长度自相矛盾（s01/02/03/08/09/18） | WARN | 当前条目按 ustar 头正常返回，但**整个畸形 pax 体已被丢弃**，不会用其中任何属性构造条目 | 安全；边界不歪 |
| pax size 数值越界/负值（s04/05/27/28） | FATAL | 否，直接终止 | 安全 |
| 流截断（s10/11） | FATAL | 否 | 安全 |
| 超大扩展体（s25） | WARN | 跳过扩展体后返回其后的真实条目 | 安全 |
| 坏校验和块（s29） | RETRY | 否，重同步后只给真实条目 | 安全 |
| 非法数字 size（s14/s31） | **OK（无告警）** | **是，且尺寸被污染** | **F1 缺陷** |
| pax/ustar 块边界冲突（s22） | OK | 是，数据区被重解释为条目 | F2，三实现共有 |

唯一"带错误信号仍交付"的情形是 WARN 类，而 WARN 时 pax 体已整体作废、条目仅反映 ustar 头，
属于可被调用方通过 `archive_errno`/返回码感知的显式降级，不算"伪有效"。
真正无信号的污染只有 F1。

---

## 6. 缺陷详述与修复建议

### F1（建议修复）：pax 数值字段尾部垃圾被静默接受

- 位置：`pax_attribute_read_number()`（tar.c:2450）调用 `tar_atol10()`，后者
  `tar_atol_base_n()`（tar.c:3627-3630）遇非数字字符直接 `break`。
- 复现：s31 中 `13 size=4abc\n`，ustar 头 size=9。libarchive 返回 ARCHIVE_OK，
  条目 size=4，只交付 4 字节；GNU tar 报「invalid size=4abc」并保留 ustar 的 9；
  Python 令该属性失效（size=0）。
- 安全影响：攻击者可在不触发任何告警/非零返回码的情况下改变条目消费长度。
  单独看本库它仍维持 512 对齐（填充由 pax 值重算），但 (a) 调用方拿不到任何异常信号，
  (b) 与 GNU tar 的解压结果产生字节级分歧，可用于针对多解析器管线的解析差异利用
  （例如杀毒/扫描器与解压端看到不同文件长度）。
- 修复建议（最小侵入）：让数字解析感知"是否消费了全部字符"。新增严格包装：

  ```c
  /* tar_atol_base_n 增加返回剩余未消费长度，或新增严格版本 */
  static int
  pax_attribute_read_number_strict(struct archive_read *a, size_t value_length,
                                   int64_t *result)
  {
      /* 复用现有读取逻辑后，校验缓冲内每个字符均为十进制数字（允许前导空格） */
      if (as.s[0] == '\0' ||
          memchr(as.s, '\0', archive_strlen(&as)) ... /* 含非 [0-9] 即拒绝 */) {
          archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                            "Malformed pax numeric attribute");
          *result = 0;
          return ARCHIVE_WARN;   /* 与其它畸形记录一致：WARN 并丢弃该属性 */
      }
      ...
  }
  ```
  对 `size`/`uid`/`gid` 等关键字走严格版：遇非法字符返回 WARN 且**不置位**
  `TAR_SIZE_PAX_SIZE`，回退到 ustar size（向 GNU 行为靠拢），而不是采纳部分解析值。
  注意 `mtime` 等浮点字段由 `pax_time()` 单独处理，不应受此改动影响。
- 回归测试：把 s31 固化为 `libarchive/test/test_read_format_tar_pax_*.c` 用例，
  断言返回码含 WARN 且 `archive_entry_size()` 等于 ustar 值 9。

### F2（建议加固，非本实现独有）：pax/ustar 尺寸跨块边界时无一致性校验

- 位置：`header_common()` tar.c:1395-1421 与 `entry_padding` 计算 tar.c:1942/2259。
- 复现：s22（ustar=513/pax=0）使数据区首块被重解释为新条目；s23（ustar=0/pax=1024）
  使真实条目被当数据隐藏。GNU tar 1.35 与 Python tarfile 行为完全相同，
  说明这是"pax 全面覆盖 ustar"规格语义的共有结果，POSIX 未要求两尺寸的块跨度一致。
- 建议（兼容性优先，默认不改变合法归档行为）：
  1. 在 `header_common()` 中，当 pax size 存在且
     `(pax_size + 511) / 512 != (ustar_size + 511) / 512`（块跨度不同）时，
     至少发出一次 `ARCHIVE_WARN`「pax size changes on-disk framing relative to ustar header」，
     让安全敏感调用方能够感知边界被重解释；当前 s22 是静默 OK。
  2. 提供一个严格选项（如 `ARCHIVE_OPTION_PAX_STRICT_FRAMING`，或复用现有 option 机制），
     启用后把块跨度不一致判为 FATAL，供解压器/扫描器在对抗场景下使用；默认关闭以兼容
     GNU/Python 与现存合法归档（s06/s07 等块跨度相同的覆盖不受影响）。
  3. 文档中明确：libarchive 以 pax size 作为物理消费长度，ustar size 在 pax 存在时
     不参与边界计算。
- 不建议直接改成"始终按 ustar size 跳过物理块"：那会破坏 s26 这类 >8 GiB 的合法 pax
  归档（ustar 字段根本无法容纳真实尺寸）。

### F3/F4（兼容性差异，可选改进）

- F3（s16/s17）：单条畸形即作废整个 pax 体。可改为记录级隔离——跳过当前畸形记录、
  继续解析体内后续合法记录，与 GNU tar 对齐；但需保证跳过长度仍受 `ext_size` 钳制
  （现有 `line_length > ext_size` 检查已经提供了这个安全前提）。
- F4（s20）：`g` 头中的标准关键字按 POSIX 应作为后续条目默认值。当前直接 FATAL 过严，
  可改为 WARN 并按默认值语义应用，或至少在文档中声明本实现不支持全局默认值。

---

## 7. 合法 PAX 归档兼容性验证（证明防线不误伤正常文件）

| 验证样本 | 内容 | libarchive | GNU tar | Python |
|---|---|---|---|---|
| s12（自构造，全合规） | 147 字节长 UTF-8 路径（长度字段经定点算法自洽）+ `size=5` 覆盖 + 浮点 `mtime=1700000000.123456789`，两个常规条目 | 两个条目均正确，消费 5120/5120，0 越界；UTF-8 告警仅因测试机 locale 非 UTF-8（`LANG=C.UTF-8` 下为路径解码问题与解析无关，条目仍可用） | rc=0 正常列出/解包 | 正常，路径与数据一致 |
| s06/s07/s13 | 合法的 pax 尺寸覆盖、重复 size（后者胜） | 全部 OK，边界精确 | 一致 | 一致 |
| s26 | pax size=9 GiB（超出 ustar 八进制字段容量的正当用途） | 条目 size=9663676416 正确建立；因样本无对应物理数据，读 body 时按预期 FATAL「Truncated ... reading data」 | — | — |
| GNU 真实归档 `runs/gnu_real.pax` | GNU tar 1.35 `--format=pax` 生成，含长路径、UTF-8 文件名、目录、普通文件 | 6 个条目全部识别，4 个文件经 bsdtar 解包成功（rc=0） | 原生 | — |
| GNU 9 GiB 稀疏归档 `runs/gnu_sparse.pax` | `truncate -s 9G` + `tar --pax --sparse`，含 `GNU.sparse.*` 扩展 | 条目 size=9663676416 正确，10 KiB 归档无异常 | 原生 | — |
| 双向互通 | bsdtar `--format=pax` 生成 → GNU tar 读取 | GNU rc=0 列出 | — | — |

结论：所有自洽、合规的 PAX 覆盖（包括最关键的 >8 GiB 尺寸覆盖）在三个实现间互通，
第 6 节的加固方案不会影响这些合法路径（F1 严格化只针对含非数字字符的非法值，
F2 默认仅新增告警/可选严格模式）。

---

## 8. 复现方法

```bash
# 构建（无容器）
cd work/build && cmake -DENABLE_TEST=OFF <repo> && make -j bsdtar archive_static
cd ../build-asan && cmake -DCMAKE_C_FLAGS="-g -O1 -fsanitize=address,undefined" <repo> \
  && make -j archive_static
bash work/scripts/build_harness.sh

# 生成 31 个样本并跑三实现差分
python3 -I work/scripts/gen_samples.py
python3 -I work/scripts/gen_probes.py
python3 -I work/scripts/gen_desync.py
python3 -I work/scripts/run_differential.py        # 输出 work/differential_runs.txt
python3 -I work/scripts/layout_dump.py             # 字节布局 work/layouts.txt

# 单样本观察消费位置（位置来自 archive_filter_bytes）
work/scripts/harness work/samples/s22_desync_pax0_ustar513.tar
ASAN_OPTIONS=detect_leaks=0 work/scripts/harness_asan work/samples/s31_silent_truncation.tar
```

所有不可信样本均位于独立目录 `work/samples/`，生成器/测试桩位于 `work/scripts/`，
Python 一律以 `python3 -I` 运行，未在样本目录内执行任何解释器或构建工具。
