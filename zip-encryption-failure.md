# ZIP 加密读取路径失效分析（恶意同时伪造 AES 强度 / 盐值 / 校验值 / 数据长度 / 口令回调耗尽）

- 代码基线：`4a5944b`（`task/98`，libarchive 主分支）
- 主体文件：`libarchive/archive_read_support_format_zip.c`（4835 行）
  口令轮换：`libarchive/archive_read_add_passphrase.c`
  密钥实现：`libarchive/archive_cryptor.c`、`libarchive/archive_hmac.c`
- 构建：本机无 autotools/cmake/flex，用手写 `config.h` + `gcc`/`ar` 直接编译（OpenSSL 3.0.13、zlib；无 liblzma/bz2/zstd，故 zipx 分支未参与运行验证，仅做源码审计）
- 全部结论均由本地生成样本 + 受控驱动实测，样本与工具在 `/srv/fb2/mei8085/0098-lab/`

---

## 0. 结论摘要

| 编号 | 问题 | 严重度 | 实测判据 |
|---|---|---|---|
| F1 | **WinZip AES 认证码校验失败后，明文仍被交付给调用方**（stored 条目先整条交付、再报错；deflate 条目先交付若干满块、最后一块才报错） | 高 | `aes_big_authbad_stored`：`archive_read_data_into_fd()` 返回 `ARCHIVE_WARN(-20)`，但文件里已有 1048576 字节未认证明文；`aes_big_authbad_deflate` 先交付 3×256 KiB 才报错 |
| F2 | **口令耗尽时无全局预算**：`retry > 10000` 是每个条目、每次 `read_data` 各算一次，失败状态不粘滞 | 高 | 单条目 1 次读 = 10002 次 PBKDF2（13.7 s）；同一失败条目再调 2 次读 = 20004 次；`n` 个伪造条目 × `M` 个候选口令 = `n·M` 次 |
| F3 | **PBKDF2 派生的密钥在 `init_WinZip_AES_decryption` 返回后仍完整留在栈上** | 中高 | 用 interposer 取得 `derived_key[]` 指针，函数返回后 `archive_read_data_block()` 一次即读到 **66/66 字节全部正确** |
| F4 | **回调口令被无限追加进持久链表**，不随条目/失败释放 | 中 | 10002 个 4 KiB 口令 → RSS 45.7 MiB（同数量短口令 6.4 MiB），量级与口令总字节数成正比 |
| F5 | 传统 PKWARE 只有 1 字节校验；口令错时被错误归类为"CRC 错"；CRC 也可由攻击者伪造 | 中（分类） | 错误口令越过 1 字节校验后报 `ZIP bad CRC` 而非 `Incorrect passphrase`；`trad_fully_forged` 在已知口令下 `rc=0` 写出攻击者数据 |
| F6 | strong-encryption（`ZIP_STRONG_ENCRYPTED`）头部解析**实际不可达**：`flags & 0xf000` 的 switch 分支与紧随其后的 `==0 || ==0x4000` 判断互相矛盾 | 低（死代码） | 16 个高半字节值全部返回 `Unknown encryption flag`；任何值都到不了 `read_decryption_header()` 的正常路径 |
| F7 | strong 头部解析中途失败时已消费字节、`init_decryption` 未复位，**重入会解到错位偏移** | 低 | `strong_reparse`：第 1 次 `ARCHIVE_FAILED`，第 2 次变 `Corrupted ZIP file data`（从头重解） |
| F8 | `ARCHIVE_FATAL`（格式/截断）会**终止整个归档**，后续合法条目不可达；`ARCHIVE_FAILED`（口令类）可继续 | 设计缺陷 | `mixed_forged_first`：伪造条目后面的 `legit.txt` 永远读不到；`mixed_macbad_first` / `mixed_pvbad_first` 中 `legit.txt` 正常读出 |
| F9 | 截断 / 长度伪造**未发现越界读写** | — | 对 15 个加密样本做全长度截断 + 全偏移单字节变异扫描（含 ASAN+UBSAN），0 命中 |

**一句话**：恶意 ZIP 能让一次"读一个条目"的调用花 13.7 s CPU、能在一次"失败"后仍把未认证明文写进输出、能把整条派生密钥留在栈上；但它不能造成越界读写，也不能让后续合法条目被无声跳过（遇到 `ARCHIVE_FATAL` 时是显式失败）。

---

## 1. 必须区分的三种失败

读代码 + 实测后，加密 ZIP 的失败实际分三类，但**对外只暴露两种状态码**，这是 F1/F2 的根源。

### 1.1 失败的三个真实来源

**(a) 密码错误**——口令校验值不匹配
- WinZip AES：`derived_key[key_len*2]`/`[+1]` 与条目内 PV 比对（`archive_read_support_format_zip.c:3490`）
- 传统 PKWARE：12 字节加密头的最后一个字节与 `zip->entry->decdat` 比对（`:3420`）

**(b) 格式错误 / 数据损坏**——结构不自洽
- 强度不在 1..3（`:3457-3461`）、`0x9901` extra 短于 6 字节（`:1210-1214`）、`remaining_size` 越界（`:3197-3198`）、`erd_size + 16 > remaining_size`（`:3268-3271`）、保留字段非 0（`:3293-3296`）、`v_size` 溢出（`:3308-3311`）

**(c) 回调耗尽**——`__archive_read_next_passphrase()` 返回 `NULL`
- `retry == 0` → `"Passphrase required for this entry"`；`retry > 0` → `"Incorrect passphrase"`；`retry > 10000` → `"Too many incorrect passphrases"`

### 1.2 对外信号（实测 `archive_errno`）

| 情形 | 返回码 | `archive_errno` | 文本 |
|---|---|---|---|
| PV / decdat 不匹配 | `-25 FAILED` | `-1` MISC | `Incorrect passphrase` |
| 无口令且无回调 | `-25 FAILED` | `-1` MISC | `Passphrase required for this entry` |
| 10002 次候选全失败 | `-25 FAILED` | `-1` MISC | `Too many incorrect passphrases` |
| 强度非法 / 无 AES extra | `-30 FATAL` | `22` EINVAL | `Corrupted ZIP file data` |
| AES extra 过短（头阶段） | `-30 FATAL` | `22` EINVAL | `Incomplete AES field` |
| 认证码不匹配 | `-20 WARN` | `-1` MISC | `ZIP bad Authentication code` |
| CRC 不匹配 | `-25 FAILED` | `-1` MISC | `ZIP bad CRC: ...` |
| 压缩数据提前结束 | `-30 FATAL` | `-1` MISC | `ZIP decompression failed (-3)` |
| AES 头被截断 | `-30 FATAL` | `22` EINVAL | `Truncated ZIP file data` |

**问题**：三类语义（密码/格式/回调）在 `errno` 上只靠 `-1` 与 `22` 区分，而"密码错"和"回调耗尽"完全同码同文本族（只差措辞）。调用方无法程序化区分"重试有意义"与"文件本身是伪造的"。

### 1.3 状态码语义错配

`ARCHIVE_WARN(-20)` 的文档含义是 **partial success**（`archive.h:236`），但认证码失败被归为 `ARCHIVE_WARN`（`:1667`）。结果是：**调用方按常规"WARN 可容忍"逻辑处理，就会把未认证数据当作已认证数据**——见 F1。

---

## 2. F1：认证失败后明文仍被交付（核心问题）

### 2.1 代码路径

AES 逐块处理在 `check_authentication_code()` 里完成（`:1637-1671`）：

```c
cmp = memcmp(hmac, p, AUTH_CODE_SIZE);
__archive_read_consume(a, AUTH_CODE_SIZE);
if (cmp != 0) {
        archive_set_error(..., "ZIP bad Authentication code");
        return (ARCHIVE_WARN);          /* :1667 —— 不是 FATAL/FAILED */
}
```

而 `zip_read_data_none()`（stored 路径）在**校验之前**就已经把数据算进输出：

```c
zip->entry_bytes_remaining -= bytes_avail;
zip->entry_uncompressed_bytes_read += bytes_avail;   /* :2065-2067 */
zip->unconsumed += bytes_avail;
*size = bytes_avail;
*_buff = buff;                                       /* 明文指针已交给上层 */
return (ARCHIVE_OK);
```

认证码只在**下一次**调用里才检查（`:2025-2030`：`entry_bytes_remaining == 0` 时 `check_authentication_code(a, NULL)`）。因此时序是：

1. 调用 `read_data` → 返回 `ARCHIVE_OK` + 全部明文块
2. 再调 `read_data` → 此时才做 HMAC 比较 → `ARCHIVE_WARN`

对**流式可解压条目**（deflate/lzma/ppmd/xz/zstd）：`zip_read_data_deflate()` 只在 `end_of_entry` 的那一次调用里检查 HMAC（`:3144-3149`）。因此**只有最后一块**与认证失败落在同一次调用；此前所有已解出的块都已按 `ARCHIVE_OK` 交付。实测 1 MiB deflate 条目：

```
$ ./blk_trace samples/aes_big_authbad_deflate/sample.zip "correct horse battery staple"
BLK0 r=0 size=262144 off=0        err=-        ← 已交付
BLK1 r=0 size=262144 off=262144   err=-        ← 已交付
BLK2 r=0 size=262144 off=524288   err=-        ← 已交付
BLK3 r=-20 size=0 off=786432      err=ZIP bad Authentication code
```

即 786 432 字节在认证失败前就已交给调用方，且每块都返回 `ARCHIVE_OK`。可解压条目并不比 stored 安全，只是"未认证字节数"被块大小切分而已。

### 2.2 实测证据

**（i）1024 KiB stored 条目，仅翻转认证码最后 1 字节**

```
$ ./extract_fd samples/aes_big_authbad_stored/sample.zip "correct horse battery staple"
EXTRACT big.txt -> rc=-20 bytes=1048576 err=ZIP bad Authentication code
```

1024 KiB 未认证明文完整落地，而函数返回 WARN。

**（ii）deflate 条目，同一伪造**

```
$ ./extract_fd samples/aes_big_authbad_deflate/sample.zip "correct horse battery staple"
EXTRACT big.txt -> rc=-20 bytes=786432 err=ZIP bad Authentication code
```

**（iii）伪造 PV + 错误密钥（攻击者控制密钥，受害者提供能被头部接受的口令）**

```
$ ./extract_fd samples/aes_pv_forged_wrongkey_stored/sample.zip "password-the-victim-supplies"
EXTRACT forgedpv_stored.txt -> rc=-20 bytes=1800 err=ZIP bad Authentication code
$ head -c 8 extracted.out | xxd
00000000: ab3d 6195 8ea4 b511            ← 攻击者密钥解出的可控数据
```

这里 PV（2 字节）由受害者口令派生、密文由攻击者密钥加密。PV 检查通过 → 攻击者控制"能过密码校验"的假象；HMAC 失败只产生 WARN；1800 字节可控数据写盘。**这是把 WARN 当"部分成功"的直接后果。**

**（iv）块级 API 更清楚**

```
$ ./blk_trace samples/aes_pv_forged_wrongkey_stored/sample.zip "password-the-victim-supplies"
HDR forgedpv_stored.txt
BLK0 r=0 size=1800 off=0 err=- first8=ab3d61958ea4b511   ← 未认证明文，返回 OK
BLK1 r=-20 size=0 off=1800 err=ZIP bad Authentication code
```

### 2.3 为什么这是真实风险而不是理论问题

- **bsdtar 自己就会留下这些文件**。`tar/read.c:366-381`：`archive_read_extract2()` 返回 WARN 后只打印一条告警并置 `return_value = 1`；因为不是 `ARCHIVE_FATAL`，循环不 `break`，也不删除已写出的文件。用户看到的是"解压时有告警"，磁盘上是完整明文。
- `ARCHIVE_WARN(-20)` 的文档含义是 **partial success**（`archive.h:236`），libarchive 内部典型判断是 `if (r < ARCHIVE_WARN)` 才当真失败（`archive_read_extract2.c:92,101,143`）。WARN 落在"可继续"一侧。
- AE-2 规范里 CRC 恒为 0，HMAC 是**唯一**完整性校验；一旦它退化成 WARN，AE-2 条目就完全没有可靠性保证。
- 攻击面：任何把"解压结果"与"是否可信"解耦的调用方（批量解包、内容索引、压缩包预览）都会中招。

### 2.4 有界失败方案（F1）

1. `check_authentication_code()` 的失败返回值从 `ARCHIVE_WARN` 改为 `ARCHIVE_FATAL`（或至少 `ARCHIVE_FAILED`），与 `ARCHIVE_ERRNO_FILE_FORMAT` 搭配。这保证任何"已交付但未认证"的块在**同一归档**内不会被当作可信。
2. 更彻底：把 stored 路径改成"先解密到缓冲 → 校验 HMAC → 再交付"，即在 `zip_read_data_none()` 里延迟一个块再输出；`decrypted_buffer` 已存在（256 KiB），无需新分配。
3. 如果为兼容性必须保留 WARN，则文档必须明确"AE-2 条目的 WARN 意味着数据未认证，调用方不得持久化"，并新增一个 `archive_entry_is_data_authenticated()` 之类的查询（当前 API 无此能力）。

---

## 3. F2：口令轮换的无界时间放大

### 3.1 代码机制

两个重试循环结构相同（传统 `:3402-3428`，AES `:3467-3499`）：

```c
for (retry = 0;; retry++) {
        passphrase = __archive_read_next_passphrase(a);
        if (passphrase == NULL) { ... return ARCHIVE_FAILED; }
        ...derive + verify...
        if (retry > 10000) { "Too many incorrect passphrases"; return ARCHIVE_FAILED; }
}
```

`__archive_read_next_passphrase()`（`archive_read_add_passphrase.c:137-189`）的行为：

- 每轮从链表头取一个候选；候选耗尽后调用 `callback`；
- 回调返回非 NULL 就**新建节点插入链表头**并令 `candidate = 1`（`:179-183`）——所以只要回调一直返回口令，循环永不因"没有候选"自然结束，只能撞上 `retry > 10000`。

因此 `retry > 10000` 是一个"每条目、每 read_data 调用"的局部上限，不是全局预算。

### 3.2 实测放大

**单条目，回调持续返回错误口令**

```
reads=1  KDF calls=10002   CALLBACKS 10002   ELAPSED_MS 13716
reads=2  KDF calls=20004   CALLBACKS 20004   ELAPSED_MS 26472
reads=3  KDF calls=29077   CALLBACKS 29077   ELAPSED_MS 38236
```

关键点：**失败不粘滞**。第 1 次 `read_data` 返回 `ARCHIVE_FAILED` 后，再调用会**重新跑一遍完整循环**（第 3 次因 `zip->init_decryption` 已被清 0 而直接进解压器，于是变成 `decompression failed`）。

**多条目线性叠加**（每个伪造条目都让回调耗尽一次）

```
entries=1  KDF=10002
entries=2  KDF=20004
entries=6  KDF=60012   （4096 字节口令，RSS 45.5 MiB，82 s）
entries=12 KDF=120024  （同一回调，164 s）
```

**`n` 条目 × `M` 候选口令**（候选来自 `archive_read_add_passphrase()` 预置列表，不触发回调上限，直接 `n·M`）

```
entries=300, M=1   → KDF=300
entries=300, M=10  → KDF=3000
entries=300, M=100 → KDF=30000   （300 条目 × 100 口令全试，每条目都从头试）
```

最后一行说明：**同一份候选口令列表在每条目上被完整重试**。恶意归档只要放 300 个伪造条目，就能把"每个条目各自 100 次 PBKDF2"放大成 30000 次（每次 1000 轮 SHA-1）。

### 3.3 与目录大小解耦的放大因子

令：
- `n` = 归档中伪造加密条目数（攻击者任意控制，上限是 ZIP 结构允许的 65535）
- `M` = 调用方提供的候选口令数（典型 1..10，交互式 bsdtar 由用户输入）
- `T_kdf` = 一次 PBKDF2-SHA1(1000 轮, AES-256 66 字节输出) 的耗时（本机 ≈ 1.3 ms）

总 CPU ≈ `n · min(M, 10002) · T_kdf`。

本机实测 12 条目 × 10002 候选 = 164 s（`scale_12` 的 `ELAPSED_MS 164588`，归档仅 1642 字节）。把 `n` 提到 1000（单个 ZIP 很容易做到：每个条目 ≈ 137 字节，含 local header、文件名、AES 盐/PV/认证码与 central directory）→ 约 3.7 小时，而**归档体积只有约 134 KiB**。这是典型的"小文件、巨量 CPU"解压炸弹变体。

### 3.4 有界失败方案（F2）

1. **全局口令预算**：在 `struct archive_read` 里放 `passphrase_attempts_budget`（默认如 10000），所有条目共享，耗尽即 `ARCHIVE_FATAL`。这与"每条目 10000"语义不同，能真正给整个会话封顶。
2. **每条目只试当前候选集一次**：`retry` 上限改成"链表长度 + 1 次回调"，而不是硬编码 10000。当前实现里回调被调用 10001 次本身就说明上限与候选集无关。
3. **失败粘滞**：在 `struct zip` 里记录 `decryption_failed_entry`（条目指针或 local_header_offset）；同一 `read_data` 在失败后再次被调用应直接返回相同错误，而不是重跑 KDF。这能消除 `reads=2` 时的 2× 放大。
4. **可配置**：把上限暴露为 `archive_read_set_option(a, "zip", "passphrase_attempts", N)`，默认值取小（如 100），需要暴力枚举的调用方自行调大。
5. **PBKDF2 迭代数**：AE 规范固定 1000 轮，不能改；但可以对"同一盐值 + 同一候选口令"做记忆化（当前无缓存，重复读同一条目会重复推导）。

---

## 4. F3：派生密钥在栈上未清零

### 4.1 代码

`init_WinZip_AES_decryption()`（`:3443-3533`）：

```c
uint8_t derived_key[MAX_DERIVED_KEY_BUF_SIZE];   /* 66 字节，栈数组 */
...
for (retry = 0;; retry++) {
        ...
        memset(derived_key, 0, sizeof(derived_key));      /* :3478 每轮开头清 */
        r = archive_pbkdf2_sha1(passphrase, ..., derived_key, key_len * 2 + 2);
        ...
}
r = archive_decrypto_aes_ctr_init(&zip->cctx, derived_key, key_len);       /* 拷进堆 ctx */
r = archive_hmac_sha1_init(&zip->hctx, derived_key + key_len, key_len);    /* 拷进堆 ctx */
...
return (zip_alloc_decryption_buffer(a));    /* :3524 */
```

`memset` 只在**每轮循环开头**；成功后直接 return，**没有在离开函数前清零**。源码里该函数内 `memset(derived_key` 出现次数 = 1，位置在循环体顶部。

### 4.2 实测证据（决定性）

用 `LD_PRELOAD` 拦截 `PKCS5_PBKDF2_HMAC_SHA1`，记录 libarchive 传入的 `out` 指针（就是 `derived_key[]` 的地址），在 `archive_read_data_block()` 返回后读该地址：

```
$ PAT=$(python3 -I -c "import json;m=json.load(open('samples/aes_valid_stored/meta.json'));print(m['key']+m['mkey']+m['pv'])")
$ LD_PRELOAD=./kdfprobe.so ./key_after_return samples/aes_valid_stored/sample.zip "correct horse battery staple" "$PAT"
rc=0 size=1000 resolved_at=0x7fff3d9621f0 key_bytes_still_correct=66/66
```

`resolved_at` 指向的栈地址上，**66 字节 `key(32) || mackey(32) || pv(2)` 全部与离线独立计算的 PBKDF2 输出一致**。三种强度都验证过：

```
aes_valid_stored (strength 3, 66B)  rc=0    key_bytes_still_correct=66/66
aes_s2           (strength 2, 50B)  rc=-25  key_bytes_still_correct=50/50
aes_s1_stack     (strength 1, 34B)  rc=0    key_bytes_still_correct=34/34
```

失败路径同样残留（`aes_s2` 那次是 `uncompressed data is larger than declared` 的失败读，密钥仍在）。

其余对照：

- 若在 `archive_read_data()`（而非 `data_block`）之后检查，因为中间压了大缓冲区等帧，只剩前 8 字节匹配——说明残留能否幸存取决于后续调用栈，**库自身没有任何保证**。
- 对照组（把期望模式换成随机字节）：`key_bytes_still_correct=0/66`，排除"扫描器自证"。
- 这也解释了为什么"盲扫整个栈"的工具（`tools/keyresidue.c`）会稳定报 0：它自己的 64 KiB 读缓冲正好覆盖了那块栈。**本节的结论只依赖 `key_after_return` 的精确地址读**，不依赖盲目扫描。

### 4.3 堆上的密钥反而被清了

`archive_decrypto_aes_ctr_release()` 与 `archive_hmac_sha1_cleanup()` 在 OpenSSL 后端里确实清零（`archive_cryptor.c:411-417`，`OPENSSL_cleanse` 在 `:414-415`）。实测用 `freeseek.so` 扫描所有 `free()` 堆块，AES key / HMAC key 命中数 = 0；而作为阳性对照的 salt（明文元数据）命中 4 次，证明扫描器有效。

**即：堆上清了，栈上没清。**

### 4.4 风险

- 同进程内后续任何代码（含攻击者可控的解压器、插件、另一个归档）都能从栈残留里取到密钥；`derived_key` 同时含 AES 密钥与 HMAC 密钥，等于把"认证密钥"也交出去，可伪造后续认证码。
- 与 F2 叠加：10002 次失败尝试意味着栈上留下的是**最后一个候选口令的派生密钥**；若攻击者能让受害者先试自己的口令再泄露栈，就能反推候选口令。
- 传统 PKWARE 的 `trad_enc_ctx`（`keys[3]`）同样在 `zip->tctx` 里，条目切换时只置 `tctx_valid=0`（`:3897`、`:4749`）而不清零。源码中对该结构没有任何 `memset`/清零调用（`grep memset(zip->` 只命中 `entry`、`zipx_lzma_stream`、`bzstream`），属同类问题（未单独做栈实验，属源码审计结论）。

### 4.5 有界失败方案（F3）

1. 所有成功/失败返回路径前 `memset(derived_key, 0, sizeof(derived_key))`，且用 `explicit_bzero` / `OPENSSL_cleanse` 防止被优化掉（普通 `memset` 在 -O2 下可能被 DCE）。
2. CMake/configure 增加 `HAVE_EXPLICIT_BZERO` 探测，提供 `la_cleanse()` 封装。
3. 条目切换与 cleanup 时清零 `zip->tctx`（传统路径的 3 个 32 位 key）。
4. 可加 `-fzero-call-used-regs=used` 之类编译选项，减少寄存器残留。

---

## 5. F4：回调口令无限缓存

### 5.1 代码

`__archive_read_next_passphrase()` 在回调返回非 NULL 时：

```c
p = new_read_passphrase(a, passphrase);   /* strdup */
if (p == NULL) return NULL;
insert_passphrase_to_head(a, p);          /* 永久挂在 a->passphrases 链上 */
a->passphrases.candidate = 1;
```

链表只在 `archive_read_free()` 时整体释放（`archive_read.c:1198-1208`）。条目切换只 `__archive_read_reset_passphrase()`（把 `candidate` 置 -1），**不释放链表**。所以：

- 每个被回调返回的口令都会 `strdup` 一份并永久保留；
- 10002 次失败 → 10002 个节点；
- 每个条目都重复一次（链表不跨条目复用成功结果，只是继续追加）。

### 5.2 实测

```
10002 × 4 KiB 口令  → MAXRSS_KB 45696  (45.6 MiB)     [aes_valid, 单条目]
10002 × ~4 B 口令   → MAXRSS_KB  6528  ( 6.4 MiB)     [aes_valid, 单条目]
10002 × 4 KiB, 2 条目 → MAXRSS_KB 45568 / 45568        [scale_2, 两条目各耗尽一次]
```

RSS 与"回调返回的口令总字节数"成正比（2 条目时 RSS 不翻倍，因为首个条目的 10002 个 4 KiB 口令已占主导；条目数只增加少量节点开销）。攻击者不控制调用方的回调，但**控制条目数**（F2），因此可以把"每个条目 10002 次回调"叠加成"每条目 10002 × 口令长度"的累计分配——即使 `reset_passphrase` 不释放，链表也只在 `archive_read_free` 时统一回收，所以峰值 ≈ `Σ(口令长度)`。

### 5.3 有界失败方案（F4）

1. 只缓存**预置**口令（`archive_read_add_passphrase`）与**最近一次**回调结果，不把回调结果插入持久链表；或在节点上记 `from_callback` 标志，条目结束时释放。
2. 给链表加长度上限（如 64）与总字节上限（如 64 KiB），超限即 `ARCHIVE_FATAL`。
3. `reset_passphrase` 时清空并释放回调来源的节点。
4. 释放前用 `explicit_bzero` 清零口令字节（当前 `archive_read_free` 只在整表释放时 `memset`，`archive_read.c:1204`）。

---

## 6. F5：传统 PKWARE 的 1 字节校验

### 6.1 机制

`trad_enc_init()`（`:383-398`）解出 12 字节头，只把 `header[11]` 与 `entry->decdat` 比较：

```c
r = trad_enc_init(&zip->tctx, passphrase, strlen(passphrase), p, 12, &crcchk);
if (r == 0 && crcchk == zip->entry->decdat) break;
```

`decdat` 来自 local header 的 `p[17]`（或 `ZIP_LENGTH_AT_END` 时的 `p[11]`，见 `:1305-1308`）——即 DOS 时间字段的高字节（非流式时是 CRC32 的高字节），攻击者完全控制。

对一个候选口令 `P`，`trad_enc_init(P)` 恰好解出一个 `header[11]`；条目被接受当且仅当它与 `decdat` 相等。所以 1/256 是"**在 `decdat` 已定的情况下，随机口令被接受**"的概率；反过来，**攻击者若不知道受害者口令，就无法选定 `decdat` 去匹配它**。实测验证：

```
$ ./bruteforce samples/trad_fully_forged/sample.zip 5000     # 5000 个随机口令
tried=5000 accepted_with_data=0

$ ./classify samples/trad_fully_forged/sample.zip "attacker-supplied"
hdr=0 data=56320 errno=0          # 攻击者已知的口令 -> 完全接受
$ ./classify samples/trad_fully_forged/sample.zip "victim-secret-passphrase"
hdr=0 data=-25 errno=-1 msg=Incorrect passphrase
```

**因此 F5 的真实影响是分类混淆，而不是"任意口令被接受"**：攻击者知道口令时本就能正常加密，所以没有额外增益。真正的问题有两点：

1. **错误归类错误**。错误口令越过 1 字节校验后，最终以 `ZIP bad CRC`（`ARCHIVE_ERRNO_MISC`）报出，被归成"数据损坏"，而实际原因是"口令错误"。实测：

   ```
   $ ./seq_read samples/trad_wrongpw_1byte/sample.zip "attacker-supplied"
   HDR garbage.txt size=56320
     data[0] = -25  err=ZIP bad CRC: 0xff60b080 should be 0x12345678
   ```

   调用方无法据此判断该换口令还是该丢弃文件（§1 的"三类失败不可区分"）。

2. **整条解密是白做的**。越过头校验后库会完整解密 56 KiB 才在 CRC 处失败；配合 F2 的重试，单条目可被反复触发。

3. **传统加密不提供完整性**。`entry->crc32` 与数据在同一个攻击者可控文件里，攻击者可以令 `crc32` 等于其自定义数据的 CRC：实测 `trad_fully_forged` 在**已知口令**下 `archive_read_data_into_fd()` 返回 `ARCHIVE_OK` 并写出 56320 字节攻击者选定内容。这一条不构成"绕过受害者口令"，但说明传统加密条目在任何情况下都不应被当作可信数据。

### 6.2 实测

构造一个"错误口令能过 1 字节校验"的归档（把 `decdat` 设为该错误口令对应的校验字节）：

```
$ ./seq_read samples/trad_wrongpw_1byte/sample.zip "attacker-supplied"
HDR garbage.txt size=56320
  data[0] = -25  err=ZIP bad CRC: 0xff60b080 should be 0x12345678
```

即"密码错"在这一层被报成了"CRC 错"（错误分类混淆，见 §1）。另用随机候选观察存在性：

```
$ ./header_pass_rate samples/trad_twelve/sample.zip 200000
candidates=798 header_passed=12 ...
```

说明错误口令确实会越过 1 字节校验并触发整条解密。该计数受"一次失败后再次 read_data 会重复计数"影响，**不宜当作精确比率**；正确读法是：对固定 `decdat`，每个候选口令独立地以 ≈1/256 的概率越过校验（`trad_enc_init` 解出的 `header[11]` 均匀分布）。

越过头部校验的候选随后都会被 CRC 拦下——**除非攻击者同时把 `crc32` 也设为其自定义数据的 CRC**。由于 `entry->crc32` 也来自攻击者可控的同一文件，这一伪造是可行的；`trad_fully_forged` 实测在已知口令下 `rc=0` 并写出 56320 字节攻击者数据。但对**不知道受害者口令**的攻击者，这仍无法让受害者的口令被接受（见 6.1 的模型分析）。

### 6.3 有界失败方案（F5）

1. 前提：不改传统加密的密码学强度（无法在不破坏兼容的前提下加强）。要改的是**分类**：
   - 头部 1 字节只作快速筛除；
   - CRC 失败时，若该条目还从未有过"通过头部校验的候选"，报"口令错误"；否则报"口令错误或数据损坏"；
   - 两者都用专用 `errno`（§10.2），不要落进 `ARCHIVE_ERRNO_MISC`。
2. `ZIP bad CRC` 在加密条目上应归为 `ARCHIVE_FATAL` 而不是 `FAILED`（当前 `:3656`），避免调用方在同一伪造条目上无限重试触发 F2。
3. 文档明确：传统加密不提供完整性保护，不可用于安全场景；需要完整性必须用 AE-2（且见 F1，AE-2 的 HMAC 目前也未强制）。

---

## 7. F6/F7：strong-encryption 分支的死代码与半消费

### 7.1 F6：flags 校验自相矛盾

`read_decryption_header()`（`:3243-3261`）：

```c
switch (zip->flags & 0xf000) {
case 0x0001: case 0x0002: case 0x0003:
        break;
default:
        archive_set_error(..., "Unknown encryption flag: %u", zip->flags);
        return ARCHIVE_FAILED;
}
if ((zip->flags & 0xf000) == 0 ||
    (zip->flags & 0xf000) == 0x4000) {
        archive_set_error(..., "Unknown encryption flag: %u", zip->flags);
        return ARCHIVE_FAILED;
}
```

第一个 switch 只放行 `0x0001/0x0002/0x0003`；第二个 if 再排除 `0` 和 `0x4000`——**这两个值本来就已经被 switch 拒绝了，第二个 if 是死代码**。更关键的是：真实 PKWARE strong encryption 的 flags 高半字节是 `0x1`/`0x2`/`0x3`，但这个 switch 比较的是整个高 4 位（`0x1000` 不等于 `0x0001`）。实测把所有 16 个高半字节值都跑一遍：

```
high_nibble=0 → Unknown encryption flag: 0
high_nibble=1 → Unknown encryption flag: 4096      ← 0x1000，规范里的 "password required"
...
high_nibble=f → Unknown encryption flag: 61440
```

**没有任何取值能通过这个检查**，`read_decryption_header()` 永远走不到正常解析路径，最终必然在函数末尾 `return ARCHIVE_FAILED("Encrypted file is unsupported")`（`:3333-3337`）。所以 strong encryption 实际是"完全未实现 + 死分支"，但它仍然会消费字节、分配内存（`iv`/`erd`/`v_data`）。

### 7.2 F7：半消费重入

`read_decryption_header()` 在 `archive_read_format_zip_read_data()` 里被调用，只有返回 `ARCHIVE_OK` 才清 `zip->init_decryption`（`:3570-3573`）。而 `read_decryption_header()` 在多个 `ARCHIVE_FAILED`/`ARCHIVE_FATAL` 分支上已经消费了部分字节（`__archive_read_consume` 出现在 `:3174`、`:3188`、`:3267`、`:3286`、`:3297`、`:3307`、`:3325`、`:3331`）。失败后：

- `init_decryption` 仍为 1 → 下次 `read_data` **从头再解一遍**，但流位置已经前进；
- 实测 `strong_reparse`：

  ```
  READ[0] rc=-25 err=Unknown encryption flag: 4096      ← 在 flags 检查处失败，已消费 iv_size(2) 字节
  READ[1] rc=-30 err=Corrupted ZIP file data            ← 从头再解，偏移全错
  ```

  两次失败的错误文本不同，说明第二次读到的是完全错位的数据。与此对照，`strong_ok_unsupported`（第一个高 4 位就非法）第 1 次就失败在 `Unsupported encryption format version: 33`——同样是重解出来的垃圾。

这不会越界（每次 `__archive_read_ahead` 都检查 NULL），但会产生**误导性错误**，且让"重试"行为不可预测（与 F2 的粘滞需求相反）。

### 7.3 有界失败方案（F6/F7）

1. 修正 switch：比较 `zip->flags & 0x000f`（低 4 位才是 spec 里的"protected data 类型"），高半字节另有含义；或者干脆在 `ZIP_STRONG_ENCRYPTED` 检测到时就返回 `ARCHIVE_FAILED`，不要假装解析。
2. 若保留解析，`read_decryption_header()` 应在失败时把 `zip->init_decryption` 置 0，并记录"该条目已损坏"，避免重入。
3. 把 `read_decryption_header()` 的 `iv_size`/`erd_size`/`v_size` 分配改成上限检查（当前 `iv_size` 是 16 位，最大 65535，`erd_size`/`v_size` 也受 16 位限制；已有 `remaining_size` 上限 `1<<18` 保护，未发现越界）。

---

## 8. F9：截断字段是否越界读取——否定结论

这是本任务明确要求验证的一项。做法：

1. 对以下样本做**全长度截断**（`n = 0 .. size-1`，逐字节）+ seek/stream 两种模式：
   `aes_valid`(202B)、`aes_valid_stored`(1168B)、`aes_length_at_end`(1168B)、`aes_extra_short`(174B)、`aes_pv_lie`(202B)、`aes_salt_mismatch`(208B)、`aes_trunc_forged_size`(156B)、`aes_csize_past_entry`(164B)、`trad_stored`(211B)、`strong_wellformed`(198B)、`strong_trunc_iv`(134B)、`strong_erd_overflow`(168B)、`strong_bad_remaining`(152B)
2. 对上述样本做**全偏移单字节变异**（每个偏移 × `{0x00,0x7f,0x80,0xff}` × 2 模式）
3. 全程 ASAN + UBSAN（`-fsanitize=address,undefined`），`ASAN_OPTIONS=abort_on_error=0:halt_on_error=0`

结果（每行最后是命中数）：

```
SWEEP aes_valid            size=202  find_bad=0
SWEEP aes_valid_stored     size=1168 find_bad=0
SWEEP aes_length_at_end    size=1168 find_bad=0
SWEEP aes_extra_short      size=174  find_bad=0
SWEEP aes_pv_lie           size=202  find_bad=0
SWEEP aes_salt_mismatch    size=208  find_bad=0
SWEEP aes_trunc_forged_size size=156 find_bad=0
SWEEP aes_csize_past_entry size=164  find_bad=0
SWEEP trad_stored          size=211  find_bad=0
SWEEP strong_wellformed    size=198  find_bad=0
SWEEP strong_trunc_iv      size=134  find_bad=0
SWEEP strong_erd_overflow  size=168  find_bad=0
SWEEP strong_bad_remaining size=152  find_bad=0
```

**0 次 ASAN/UBSAN 命中**。

源码层面的防护也成立：

- 所有 `__archive_read_ahead(a, N, ...)` 的返回都检查 NULL（如 `:3169`、`:3179`、`:3193`、`:3277`、`:3302`、`:3316`、`:3327`）；
- `process_extra()` 有 `offset + datasize > extra_length` 检查（`:726`），Zip64 子字段有 `datasize < 8` 检查（`:743`/`:758`/`:773`）；
- `zip->entry_bytes_remaining` 在 AES 初始化里有下溢检查 `if (0 == LENGTH_AT_END && remaining < 0) goto corrupted`（`:3516-3518`）；
- `zip_read_decrypt()` 对 `bytes_avail < 0` 有钳制（`:509-510`）。

**唯一需要注意的是**：`entry_bytes_remaining` 在 `ZIP_LENGTH_AT_END` 时不做下溢检查（`:3516` 的条件），因此长度字段伪造时可以变成任意负值；实测 `aes_trunc_forged_size` 与 `aes_csize_past_entry` 都安全地在 `__archive_read_ahead` 处被拦住（`Truncated ZIP file data`），但这依赖读取器永远不会把负的 remaining 当正数用。建议补一条无条件检查。

---

## 9. 失败路径的密钥材料清零与释放

逐项核对（源码 + 实测）：

| 材料 | 位置 | 失败时是否清零 | 失败时是否释放 |
|---|---|---|---|
| `derived_key[66]`（AES+HMAC 密钥） | 栈 | **否**（F3，仅循环顶部 memset） | 不适用（栈） |
| `zip->cctx.key[32]` | 堆 | 是（`OPENSSL_cleanse`，`archive_cryptor.c:414-415`） | 是（cleanup / 条目切换） |
| `zip->hctx` | 堆 | 是（`EVP_MAC_CTX_free` + 内部清零） | 是 |
| `zip->tctx.keys[3]` | 堆（结构体内） | **否**（只置 `tctx_valid=0`） | 不释放（随 zip 结构体） |
| `zip->iv`/`erd`/`v_data` | 堆 | **否**（`free` 前无 memset） | 是（`archive_read_format_zip_cleanup`） |
| `zip->decrypted_buffer`（明文） | 堆 | **否** | 是（`:3725`） |
| `zip->uncompressed_buffer`（明文） | 堆 | **否** | 是（`:3711`） |
| 口令链表节点 | 堆 | 仅整表释放时清零（`archive_read.c:1204`） | 仅 `archive_read_free` |

实测补充：

- **堆泄漏**：ASAN LeakSanitizer 对有效读、MAC 失败、回调耗尽三种路径均**无报告**（`leak_or_asan_reports=0`）——失败路径的 malloc 都被 `cleanup` 释放了。
- **堆密钥残留**：`freeseek.so` 扫描所有 `free()` 块，AES key / HMAC key 命中 **0**；salt 阳性对照命中 4 次。
- **明文残留**：`uncompressed_buffer` / `decrypted_buffer` 被 `free` 时**里面还有明文**（backtrace 显示 `archive_read_format_zip_cleanup:3711` 与 `:3725`）。即 `free()` 之后，明文仍留在 glibc 的已释放 chunk 中，直到被复用。对"解压到内存再处理"的调用方，这是信息泄露面。

**结论**：失败路径的**内存管理是干净的（不泄漏）**，但**密钥/明文的清除是不完整的**：栈上的 `derived_key` 与堆上的 `tctx`、`iv`/`erd`/`v_data`、两个明文缓冲区都没有在使用后清零。

---

## 10. 有界失败方案（汇总设计）

目标：任意恶意归档下，单个条目的资源消耗与错误语义都可预测、可复验。

### 10.1 资源上界

| 资源 | 当前 | 建议 |
|---|---|---|
| 单条目口令尝试 | 10002 次（每次 1 次 PBKDF2） | 每个条目只试"候选集一次"（≤ 链表长度 + 1 次回调） |
| 整个会话口令尝试 | 无上限（`n × 10002`） | 全局预算 `passphrase_budget`（默认 10000），共享，耗尽 → `ARCHIVE_FATAL` |
| 失败后重试 | 重新跑完整循环 | 失败粘滞：同一 `read_data` 直接返回上次错误 |
| 口令缓存 | 无限追加（每条目 +10002 节点） | 只缓存预置口令 + 最近一次回调结果；上限 64 节点 / 64 KiB |
| 明文交付 | 认证前交付 | 认证后再交付（stored 路径延迟一块） |
| 认证失败状态 | `ARCHIVE_WARN` | `ARCHIVE_FATAL` + `ARCHIVE_ERRNO_FILE_FORMAT` |

### 10.2 错误分类（可程序化)

建议引入独立的 `archive_errno` 语义：

| 语义 | 返回码 | errno | 是否可重试 |
|---|---|---|---|
| 口令错误（有候选） | `ARCHIVE_FAILED` | `ARCHIVE_ERRNO_PASSPHRASE`（新增，或复用 `EAUTH`） | 是（换口令） |
| 回调耗尽 / 无口令 | `ARCHIVE_FAILED` 或 `FATAL` | 同上 | 是（但受预算） |
| 格式错误 / 伪造字段 | `ARCHIVE_FATAL` | `ARCHIVE_ERRNO_FILE_FORMAT` | 否 |
| 认证失败 | `ARCHIVE_FATAL` | `ARCHIVE_ERRNO_FILE_FORMAT` | 否 |
| 压缩数据截断 | `ARCHIVE_FATAL` | `ARCHIVE_ERRNO_FILE_FORMAT` | 否 |

当前 `ARCHIVE_ERRNO_MISC(-1)` 把前两类混在一起（实测 §1.2），需要拆分。

### 10.3 密钥/明文生命周期

- `derived_key`：所有出口前 `explicit_bzero`；
- `tctx`：条目切换与 cleanup 时 `explicit_bzero`；
- `iv`/`erd`/`v_data`：`free` 前清零；
- `decrypted_buffer` / `uncompressed_buffer`：`free` 前清零（或复用前清零）；
- 口令节点：释放前清零（已有，但需覆盖回调来源的节点）。

### 10.4 兼容性

F1 的 `WARN→FATAL` 会改变既有行为（现有测试 `test_read_format_zip_encryption_data.c` 期望 `ARCHIVE_FAILED`，不受影响；但依赖 WARN 的调用方会收到 FATAL）。建议用 `archive_read_set_option(a, "zip", "strict-auth", "1")` 开关，默认严格，提供兼容回退。

---

## 11. 可复验判据（每一条都能用本地工具复现）

工具与样本位于 `/srv/fb2/mei8085/0098-lab/`：

```
build.sh / build_asan.sh   用受限 config.h 编译 libarchive.a / libarchive_asan.a
build_tools.sh             编译下面全部工具（./build_tools.sh [lib.a] [后缀]）
tools/mkzip.py             生成 AES(128/192/256, stored/deflate)、传统 PKWARE、
                           strong-encryption 头部、长度伪造、PV 伪造、认证码伪造样本
tools/driver.c             通用驱动：seek/stream、固定口令/回调/无限回调/静态4KB回调、
                           --retry-fail（失败后继续读）、--reads N
tools/probe_block.c        block 级探测（能看到失败前已交付的块）
tools/blk_trace.c          同上，打印每块前 8 字节
tools/extract_fd.c         用 archive_read_data_into_fd() 模拟提取，输出落盘字节数
tools/seq_read.c           连续多次 archive_read_data() 且遇错不停止
tools/probe_deliver.c      明文前缀比对
tools/multi_pw.c           预置 M 个口令，遍历全部条目（用于 n×M 放大测量）
tools/kdfcount.c  (LD_PRELOAD) 统计 PKCS5_PBKDF2_HMAC_SHA1 调用次数与口令字节数
tools/kdfprobe.c  (LD_PRELOAD) 额外记录 derived_key 的栈地址与派生结果
tools/key_after_return.c   函数返回后读取 derived_key 地址，与离线 PBKDF2 结果比对
tools/keyresidue.c         盲扫栈上的密钥（有自覆盖局限，见 §4.2，结论以 key_after_return 为准）
tools/freeseek.c  (LD_PRELOAD) 扫描每个 free() 块里的明文/密钥残留
tools/sweep.sh             全长度截断 + 全偏移单字节变异 + ASAN/UBSAN
run_all.sh                 一次性跑完下表全部结论（SWEEP=1 时含变异扫描）
```

**最快复验**：

```sh
cd /srv/fb2/mei8085/0098-lab
./build.sh && ./build_asan.sh && ./build_tools.sh      # 首次
./run_all.sh                                           # 逐条打印实测输出
SWEEP=1 ./run_all.sh                                   # 追加 ASAN/UBSAN 变异扫描
```

| 结论 | 复验命令 | 期望输出 |
|---|---|---|
| 有效 AES-256 可读 | `./driver --pw "correct horse battery staple" samples/aes_valid_stored/sample.zip` | `READ[0] rc=1000` |
| F1 明文先于认证交付 | `./blk_trace samples/aes_auth_forged_stored/sample.zip "correct horse battery staple"` | `BLK0 r=0 size=1800`，`BLK1 r=-20` |
| F1 未认证数据落盘 | `./extract_fd samples/aes_big_authbad_stored/sample.zip "correct horse battery staple"` | `rc=-20 bytes=1048576` |
| F1 伪造 PV + 错密钥 | `./extract_fd samples/aes_pv_forged_wrongkey_stored/sample.zip "password-the-victim-supplies"` | `rc=-20`，文件 `1800` 字节 |
| F2 单条目放大 | `LD_PRELOAD=./kdfcount.so ./driver --cb-endless 100000 --reads 1 samples/aes_valid/sample.zip` | `KDF calls=10002`，`ELAPSED_MS ≈ 13200` |
| F2 失败不粘滞 | 同上加 `--retry-fail --reads 3` | `KDF calls=29077` |
| F2 多条目线性 | `LD_PRELOAD=./kdfcount.so ./multi_pw samples/aes_many_forged/sample.zip 100` | `KDF calls=30000`，`ENTRIES 300` |
| F3 栈密钥残留 | `PAT=$(python3 -I -c "import json;m=json.load(open('samples/aes_valid_stored/meta.json'));print(m['key']+m['mkey']+m['pv'])"); LD_PRELOAD=./kdfprobe.so ./key_after_return samples/aes_valid_stored/sample.zip "correct horse battery staple" "$PAT"` | `key_bytes_still_correct=66/66` |
| F3 对照 | 把 `$PAT` 换成随机 66 字节 | `0/66` |
| F4 缓存增长 | `./driver --cb-static 10002 samples/aes_valid/sample.zip` | `MAXRSS_KB ≈ 45696` |
| F4 对照 | `./driver --cb-endless 10002 samples/aes_valid/sample.zip` | `MAXRSS_KB ≈ 6528` |
| F5 1 字节校验 | `./seq_read samples/trad_wrongpw_1byte/sample.zip "attacker-supplied"` | `ZIP bad CRC`（而非 `Incorrect passphrase`） |
| F5 CRC 可伪造 | `./seq_read samples/trad_fully_forged/sample.zip "attacker-supplied"` | `data[0]=56320 err=-`（rc=0，交付攻击者数据） |
| F6 死分支 | `for i in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do ./driver --pw x samples/strong_nib$i/sample.zip; done` | 16 个全部 `Unknown encryption flag` |
| F7 半消费 | `./driver --pw x --reads 4 --retry-fail samples/strong_reparse/sample.zip` | `READ[0] -25 Unknown encryption flag: 4096`，`READ[1] -30 Corrupted ZIP file data` |
| F8 可恢复性 | `./driver --pw "correct horse battery staple" samples/mixed_forged_first/sample.zip` | `NEXT_HEADER rc=-30`，`legit.txt` 不可达 |
| F8 对照 | `./driver --pw "correct horse battery staple" --reads 2 samples/mixed_macbad_first/sample.zip` | `legit.txt` 正常读出 `rc=180` |
| F9 越界 | `./tools/sweep.sh aes_valid` 等 15 个样本 | 每个 `find_bad=0` |
| F9 泄漏 | `SAN=1 ./build_tools.sh libarchive_asan.a _asan && ASAN_OPTIONS=detect_leaks=1 ./driver_asan --pw "correct horse battery staple" --reads 2 samples/aes_big_authbad_stored/sample.zip` | 无 `LeakSanitizer` 输出 |

---

## 12. 修复优先级

1. **P0 / F1**：认证失败不得交付明文，返回值改为 `ARCHIVE_FATAL`。这是唯一一条"直接用错数据"的问题。
2. **P0 / F2**：全局口令预算 + 失败粘滞。这是唯一一条"几十 KB 换几小时 CPU"的问题。
3. **P1 / F3**：`derived_key` 与 `tctx` 清零。
4. **P1 / F4**：回调口令不入持久链表 / 加上限。
5. **P2 / F6、F7**：strong-encryption 要么实现，要么直接拒绝，不要半解析。
6. **P2 / F5**：传统加密的错误分类与文档。
7. **P3 / F8**：区分"条目级失败"（可继续）与"归档级失败"（终止）；当前 `ARCHIVE_FATAL` 用得过宽（格式错误、截断都终止整个归档），而真正的安全失败（认证）却只给 WARN，正好相反。

---

## 附录 A：受控样本清单

| 目录 | 构造 | 用途 |
|---|---|---|
| `aes_valid` | AES-256/deflate/AE-2，合法 | 基线 |
| `aes_valid_stored` | AES-256/stored，合法 | 明文直通基线 |
| `aes_strength_{0,4,255}` | 强度字段伪造 | 格式错误分类 |
| `aes_pv_lie` | PV 翻转 | 密码错误分类 |
| `aes_pv_forged_wrongkey{,_stored}` | PV 由受害者口令派生、密文用攻击者密钥 | F1 最强证据 |
| `aes_salt_mismatch` | 声明 16B 盐，实为 8B | 长度/盐伪造 |
| `aes_trunc_forged_size` | csize/usize=0x7ffffff0，body 仅 18B | 截断+长度伪造 |
| `aes_csize_past_entry` | csize=0x00ffffff，body 18B | 越界读取尝试 |
| `aes_length_at_end` / `aes_len_at_end_dd` | `ZIP_LENGTH_AT_END`，有/无 data descriptor | 流式路径 |
| `aes_auth_forged{,_stored}` | 认证码最后一字节翻转 | F1 |
| `aes_big_authbad_{stored,deflate}` | 1 MiB 明文 + 认证码翻转 | F1 量产证据 |
| `aes_crc_lie` | AE-1 + CRC 伪造 | CRC 校验 |
| `aes_extra_short` / `aes_no_extra` | 0x9901 数据不足 / 缺失 | extra 解析 |
| `aes_many_forged` / `scale_{1,2,4,5,12}` / `aes_six_forged` / `aes_twelve_forged` | 300 / n 个 PV 伪造条目 | F2 多条目放大 |
| `aes_cand131` | 正确口令是第 131 个候选 | 轮换成功 vs 耗尽 |
| `aes_pv_false_accept` | PV 对错误口令有效、HMAC 是唯一检查 | PV 语义 |
| `aes_body_shorter_than_salt` / `aes_lae_body_short` | 声明 csize=5 小于盐+PV 长度 | 短 body |
| `aes_init_ok_no_decomp` | AES 头解析成功但压缩方法不支持 | F3 最小栈复用 |
| `aes_s1_stack` / `aes_s2` | strength 1 / 2（34 / 50 字节 derived_key） | F3 各强度 |
| `trad_stored` / `trad_deflate` / `trad_twelve` / `trad_stream_dd` | Info-ZIP 传统加密（含 LENGTH_AT_END 变体） | 传统路径基线 |
| `trad_wrongpw_1byte` | 错误口令能过 1 字节校验 | F5 |
| `trad_fully_forged` | decdat 与 CRC 同时伪造（LENGTH_AT_END 解耦） | F5 已知口令下完全接受 |
| `trad_false_accept` | 早期尝试（decdat 受 CRC 高字节耦合，未能解耦） | 构造过程记录 |
| `strong_*` / `strong_nib{0..f}` / `strong_f{0001,0002,2001,2002,2003}` / `strong_flags_*` | strong-encryption 头部各种 flags / 版本 / 算法 / 保留字段伪造 | F6/F7 |
| `strong_ok_unsupported` / `strong_reparse` / `strong_iv_huge` / `strong_v_over` | 自洽头部 / 半消费后重解 / 超大 IV / v_size 溢出 | F6/F7 |
| `mixed_forged_first` / `mixed_macbad_first` / `mixed_pvbad_first` / `many_forged_then_legit` | 伪造条目 + 合法条目（前者在前 / 后者在前） | F8 可恢复性 |

## 附录 B：编译环境说明

- 无 autoconf/automake/cmake/flex → 手写 `config.h`（`HAVE_LIBCRYPTO`、`HAVE_PKCS5_PBKDF2_HMAC_SHA1`、`ARCHIVE_CRYPTO_*_OPENSSL`、zlib），`gcc -O1 -g` + `ar`。
- 系统缺 liblzma/bz2/zstd 头文件 → 代码里 `HAVE_LZMA_H`/`HAVE_BZLIB_H`/`HAVE_ZSTD_H` 均未定义，**zipx（LZMA/XZ/BZip2/Zstd/PPMd 的加密分支）未被运行时覆盖**，仅做源码审计。PPMd 是内置实现（不依赖外部库），其 `ppmd_read()` 路径（`:302-340`）审计结论：字节级解密与 HMAC 更新顺序正确，未发现越界。
- ASAN/UBSAN 构建用同一份 `config.h` + `-fsanitize=address,undefined`。
