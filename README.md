# IoT 流量动态模拟与 QUIC 协议测试框架（C 实现）

本项目实现了你提出的三个核心模块：

- 模块 A：`libpcap` 背景流量画像 + Alias O(1) 重采样
- 模块 B：QUIC CID 注入接口 + QUIC 握手二进制重放工具
- 模块 C：动态 Padding + 伴随触发微突发发包调度器

## 1. 构建

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```

依赖：

- `libpcap`（开发头文件）
- `pthread`
- `OpenSSL`
- `git`（CMake 会自动拉取 `picoquic` 与 `picotls`）
- Linux / POSIX socket API

## 2. 代码结构

- `include/alias.h`, `src/alias.c`：Alias Method 采样器
- `include/traffic_profile.h`, `src/traffic_profile.c`：模块 A 实时流量画像引擎
- `include/quic_cid.h`, `src/quic_cid.c`：模块 B CID 注入与高熵填充接口
- `include/pico_cid_secure.h`, `src/pico_cid_secure.c`：picoquic CID 分片与 hash 认证编码层
- `tools/quic_replay.c`：模块 B QUIC 握手流重放工具
- `include/microburst_scheduler.h`, `src/microburst_scheduler.c`：模块 C 调度器核心
- `tools/microburst_main.c`：模块 C 启动入口
- `tools/profile_sampler_main.c`：模块 A 采样示例入口
- `include/quic_secure_channel.h`, `src/quic_secure_channel.c`：A/B/C 融合的安全信道核心
- `tools/quic_secure_server.c`, `tools/quic_secure_client.c`：可互通客户端/服务端

## 3. 模块 A：流量画像与重采样

### 3.1 功能

- 持续监听指定网卡（默认 BPF：`ip and udp`）
- 在线统计两个离散 PDF：
  - 包长分布 `L in [0,1500]`
  - IAT 分布 `D in [0,max_iat_ms]`
- 使用 Alias Method 将离散 PDF 预处理为 O(1) 采样表
- 通过 `tp_engine_sample()` 输出 `(Ltarget, Dnext)`

### 3.2 运行示例

```bash
sudo ./build/module_a_profiler -i eth0 -m 5000 -r 256
```

参数说明：

- `-i` 网卡名
- `-m` IAT 最大毫秒桶
- `-r` Alias 表重建间隔（按包数）

## 4. 模块 B：QUIC CID 注入与握手重放

### 4.1 注入接口（项目内）

`src/quic_cid.c` 提供：

- `quic_cid_set_entropy()`：注入外部高熵字节流
- `quic_cid_generate()`：生成 CID（1..20 字节）
- `quic_initial_patch_dcid_inplace()`：原地替换 Initial 的 DCID（等长替换）
- `quic_entropy_fill()`：给 Padding/载荷填充高熵数据

### 4.2 picoquic 改造指南（基于 upstream 当前结构）

建议优先走“回调接管 + 创建连接时显式 initial CID”两层：

1. 使用 `picoquic_create(..., cnx_id_callback, cnx_id_callback_data, ...)` 注入回调。  
   回调类型在 `picoquic/picoquic.h`：`picoquic_connection_id_cb_fn`。
2. 回调最终在 `picoquic/quicctx.c` 的 `picoquic_create_local_cnx_id()` 中被调用，可在回调内使用 `quic_cid_generate()` 覆盖 `cnx_id_returned`。
3. 客户端 Initial 的初始 CID：`picoquic_create_cnx()` 支持传入 `initial_cnx_id`。若传空，`picoquic_create_cnx_internal()` 会回退随机生成（`quicctx.c` 中 `picoquic_create_random_cnx_id(...)` 分支）。
4. 若你要“强制所有 client Initial 都来自外部高熵流”，可在该回退分支替换为你自己的生成函数（调用本项目 `quic_cid_generate()`）。

### 4.3 lsquic 改造指南（基于 upstream 当前结构）

lsquic 的 SCID 可直接通过引擎 API 回调接管：

1. 在 `lsquic_engine_api` 里设置 `ea_generate_scid` 与 `ea_gen_scid_ctx`。
2. 引擎初始化时会把该回调装配到 `engine->pub.enp_generate_scid`（`src/liblsquic/lsquic_engine.c`）。
3. 服务器侧/连接内新增 SCID 生成会调用 `enp_generate_scid(...)`（例如 `lsquic_full_conn_ietf.c`）。

对于“客户端 Initial 的 DCID（即 Initial header 中的 destination connection ID）”，默认路径在 `lsquic_full_conn_ietf.c`：

- `lsquic_generate_cid(CUR_DCID(conn), 0);`

若要注入外部高熵流，请将这一调用替换为自定义函数（内部调用 `quic_cid_generate()` 或等效逻辑），并保证 CID 长度满足 QUIC 版本约束。

### 4.4 QUIC 握手二进制重放工具

重放离线 pcap 中的 UDP 负载（保留原始时间间隔，可加速/减速）：

```bash
./build/module_b_replay -r handshake.pcap -d <dst_ip> -p 443 -x 1.0 -l 1
```

参数：

- `-r` pcap 文件
- `-d/-p` 目标地址端口
- `-x` 速度倍率（`2.0` 表示 2 倍速重放）
- `-l` 循环次数
- `-s` 可选绑定源端口

## 5. 模块 C：动态 Padding 与伴随触发调度

### 5.1 功能

- 纯 UDP 发包，构造 QUIC Initial 风格长头报文
- 从模块 A 采样 `Ltarget` 与 `Dnext`
- 若报文未达 `Ltarget`，自动使用高熵字节填充到精确长度
- `libpcap + 多线程` 伴随触发：检测业务流峰值后唤醒发送线程，执行微突发序列

### 5.2 运行示例

```bash
sudo ./build/module_c_scheduler \
  -i eth0 -d 192.0.2.10 -p 443 \
  -e entropy.bin -n 16 -w 200 -t 20 -c 16
```

参数：

- `-e` 高熵输入文件（可选）
- `-n` 每次触发的微突发包数
- `-w/-t` 峰值触发窗口与阈值
- `-c` CID 长度（1..20）
- `-F/-T` 可分别指定画像与触发的 BPF

### 5.3 说明

- 按 QUIC 规范，Initial 报文通常要求最小 1200 字节。本实现在构建 Initial 风格报文时遵守该下限。
- 该调度器用于 NIDS 状态机/边界行为测试，重点是“统计外观、时序与字段形态”可控。

## 6. 最终端到端信道（picoquic + CID 分片）

### 6.1 设计说明（当前实现）

- 基于 `picoquic` 真 QUIC 协议栈，客户端/服务端通过 `picoquic_packet_loop()` 互通。
- 每个连接的 **Initial CID** 承载一个分片，CID 格式：
  - `magic(1) + session_id(4) + frag_idx(1) + frag_total(1) + data_len(1) + frag_data(N)`
  - `cid_len<=20`，默认 `20`，单片最大 `12` 字节。
- 大消息自动分片：上行/下行都按 `session_id + frag_idx` 分片重组。
- payload 不承载明文业务数据，只承载认证哈希：
  - `hash = SHA256(PSK || CID || role_tag)`
  - 上行：`CLIENT_PROOF -> SERVER_ACK`
  - 下行：`SERVER_PUSH -> CLIENT_PUSH_ACK`
- 默认启用 `picoquic_set_null_verifier()`（实验模式），证书链校验关闭，身份由上面的 `PSK + CID` 哈希认证保证。
- 服务端维护客户端连接列表：记录 `IP / 首次消息时间 / 最近一次消息间隔 / 距今未活跃时长 / 消息计数`，超过 `1 hour` 未收到消息会自动剔除。
- 服务端可运行时下发消息到 `all` 或指定 `ip`，下发内容也放在 CID 中（必要时分片），客户端本地打印日志。
- 模块 A 结合：客户端可选通过 `-i <iface>` 启用背景流量画像采样，用采样的 `Dnext` 给分片连接节奏做 pacing。
- 客户端周期上报：默认使用 `interval = (UTC_timestamp % 60) * 60 sec`，每轮发送高熵随机变量，确保不同轮次 CID 差异显著。

### 6.2 运行服务端

先生成共享密钥（可选，推荐）：

```bash
KEY=$(openssl rand -hex 32)
echo ${#KEY}   # 64
```

运行：

```bash
./build/quic_secure_server -p 4433 -k "$KEY"
```

默认证书：

- `certs/cert.pem`
- `certs/key.pem`

可通过 `-C/-K` 覆盖。

服务端运行后支持交互命令（stdin）：

```text
list
send all <message>
send <ip> <message>
help
```

常用附加参数：

- `-c <cid_len>`：服务端下发时使用的 CID 长度（`8..20`）
- `-P <port>`：客户端监听端口（服务端下发目标端口，默认 `5544`）

### 6.3 运行客户端

客户端启动后会：

- 本地监听 `-L <listen_port>`（默认 `5544`），接收服务端下行 CID 消息并打印；
- 按周期发送上行 CID 消息（高熵内容，payload 仅做 hash 验证）。

运行示例：

```bash
./build/quic_secure_client -s 127.0.0.1 -p 4433 -k "$KEY"
```

可选参数：

- `-c <cid_len>`：CID 长度，范围 `8..20`
- `-L <listen_port>`：客户端下行监听端口（默认 `5544`）
- `-u <unit_sec>`：间隔单位秒（默认 `60`，即按“分钟”执行 `UTC%60`）
- `-e <bytes>`：每轮高熵消息长度（默认 = `cid_len - 8`）
- `-r <rounds>`：发送轮次，`0` 表示持续发送
- `-m <message>`：固定消息调试模式（会禁用高熵生成）
- `-C <ca_cert.pem>`：上行握手 CA/cert（默认 `certs/cert.pem`）
- `-E/-G`：客户端监听端证书/私钥（默认 `certs/cert.pem` / `certs/key.pem`）
- `-a <alpn>`：默认 `qsc_cid_auth_v1`
- `-n <sni>`：默认 `localhost`
- `-i <iface> -f <bpf>`：启用模块 A 的实时采样节奏

## 7. 安全与实验边界

本框架仅用于授权环境下的协议测试、NIDS 评估与学术研究。请勿在未授权网络中使用。
