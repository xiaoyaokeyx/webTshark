# WebShark · 离线抓包分析工作台

0.3 增强版：多标签、任务中心、报文构造、协议诊断、PCAP 对比与报告见 [功能与验收说明](ENHANCEMENTS.md)。

React 网页界面 + Node.js 服务 + 本机 TShark 解析引擎。上传 PCAP/PCAPNG/CAP 后进行离线分析，不提供实时抓包。目前已接入真实数据解析，但尚未覆盖 Wireshark 的全部功能。

## 已实现

- 文件上传、上传进度、解析状态、取消、历史文件管理。原始文件和解析索引保存在服务端。
- 三窗格分析：分页数据包列表、真实协议字段树、HEX/ASCII 字节视图与字段字节定位。
- 使用 TShark 的显示过滤语法，支持字段补全、保存过滤器和错误提示。无效过滤器保留上次有效结果。
- 解析中先显示首批 100 个包，后续持续更新并可翻页；完整解析结束后开放过滤、统计和协议详情。保持整份抓包的协议上下文，不按字节切断 TCP/SIP 会话。
- 服务端可配置多个自定义 Wireshark Lua 脚本；注册字段支持显示过滤、自动补全、协议详情与自定义列。
- 在数据包单元格或协议字段上右击：应用、排除、AND、OR、AND NOT、仅准备过滤器；也可显式追踪 TCP/UDP 流、标记数据包。数据包单击查看详情，取消双击追踪以避免误触。
- TCP/UDP 双向流内容、方向切换、搜索、HEX 与下载；协议分布、流量时间线、会话、端点、专家信息。
- SIP VoIP 通话时序图：按 Call-ID 分组，支持多会话合并/分组、IP 两端标识、实际时间/相对时间、消息间隔和原始 SIP 报文展开。时序图会沿用当前已应用的过滤器；无过滤器时显示抓包中的全部 SIP 会话。
- `sip_mrcp.port=12345` ASR/MRCP 关联过滤：从 SIP/SDP 音频端口关联 Call-ID、MRCP Channel-ID、MRCP TCP、RTP/RTCP 流；输入 `sip_mrcp` 时提供语法联想。宏可以嵌入普通 `AND/OR` 表达式，导出时也会自动展开并应用对应 Decode As。
- RTP 流列表：源/目标地址和端口、SSRC、PT、编解码、包数、估计丢包、重复包、抖动。
- 动态 PT 96–127 映射：设置编解码、RTP 时钟频率和声道；默认限定到单条有方向的 RTP 流，也可应用于当前抓包。同一 PT 的不同流可以使用不同编解码，流级映射优先。
- 将指定 UDP 端口解码为 RTP；可选 RTP 启发式识别。保存映射后重新解析当前文件，失败时恢复上次有效结果。
- 合成演示抓包包含一组可筛选的 SIP 呼叫信令：INVITE、100/180/200 响应、ACK、BYE；INVITE 与 200 OK 使用不同的多媒体 SDP offer/answer，包含 PCMU、AMR/AMR-WB、H.264、VP8、fmtp 和 RTCP 属性。
- SIP 报文比较：在数据包比较模式中选择两个 SIP 报文，可并排比较 SIP 头域和复杂 SDP 会话描述；支持多媒体段、重复属性、动态 PT、rtpmap/fmtp/rtcp-fb 等字段按媒体段和 PT 对齐，差异与缺失字段会高亮显示。
- PCMA/PCMU 音频试听和 WAV 导出；原始/过滤后 PCAPNG 导出；当前页 CSV/JSON 导出；浏览器本地备注。
- 数据包列表支持两行数据包比较；列标题可排序，支持按 Wireshark 常用字段隐藏、删除、添加和调整顺序。
- 数据包列表排序在服务端对完整结果集执行后再分页，不会只对当前页排序；自定义字段会按需加入索引，列定义可在浏览器刷新后恢复。
- 数据包列表每页支持 100、200、500、1000 包；列宽可拖拽调整，列顺序、隐藏状态、时间格式和视图设置保存在浏览器本地。
- 时间列支持 Seconds Since Beginning of Capture、Epoch、Local Date and Time、UTC Date and Time 四种 Wireshark 风格显示格式，布局和时间格式保存在浏览器本地。

## 本地开发

要求：

- 前端构建环境符合当前 Vite 依赖要求：Node.js 20.x（≥20.19.0），或 22.12.0 及以上版本。**Node 21 不在 Vite 7 支持范围内。**
- 已安装 TShark，且编译时启用了 Lua。此次开发验证使用 TShark 4.6.6。

```sh
node --version
tshark --version
npm ci
npm run dev
```

打开 [本地工作台](http://127.0.0.1:5173/)。开发命令同时启动 Vite（5173）和 Node API（3001），由 Vite 转发 `/api` 请求。默认监听 `0.0.0.0`，局域网设备可通过这台机器的 IP 访问。

启动时可以指定绑定 IP；`--host` 会同时设置 Vite 和 Node API 的监听地址：

```sh
# 监听指定网卡地址
npm run dev -- --host 192.168.1.50

# 或使用环境变量；需要改端口时分别指定 API/UI 端口
HOST=192.168.1.50 npm run dev -- --api-port 3001 --ui-port 5173
```

TShark 不在 PATH 时指定完整路径，例如 macOS：

```sh
TSHARK_PATH='/Applications/Wireshark.app/Contents/MacOS/tshark' npm run dev
```

首次打开时生成并解析一份合成 PCAP，包含 194 个真实格式的数据包、7 个 SIP 信令包和两条 PT 96 RTP 流，便于测试过滤、映射隔离、丢包、SIP 比较和试听。它不是用户的网络流量。

## 右键过滤与 RTP 操作

1. 在源地址、目标地址、协议等单元格，或下方协议树的字段上右击，选择过滤动作。AND/OR 会自动为原表达式和新条件加括号。
2. 打开左侧 **RTP 媒体流**，点击流旁的 **设置 PT**；选择 PT、编解码、时钟频率、声道及作用范围，保存后自动重新解析。
   AMR / AMR-WB 还可选择 Bandwidth-efficient（`octet-align=0`）或 Octet-aligned（`octet-align=1`），并分别固定使用 8000 / 16000 Hz 时钟。按 SDP 的 `a=fmtp` 参数选择；未声明时默认 Bandwidth-efficient。
3. 如果数据仍显示为 UDP，在数据包上右击选择解码为 RTP，或在 RTP 页面配置 UDP 端口。启发式识别可能误判，已知端口时优先配置端口。
4. PCMA/PCMU 映射生效后可以试听或下载 WAV。两条方向相反的流分别设置，不会因为 PT 相同而互相覆盖。

### ASR/MRCP 关联过滤

在过滤器输入框中可使用 `sip_mrcp.port=12345`（也支持 `==`、`eq`，以及 `media_port`/`rtp_port` 别名）。输入 `sip_mrcp` 或 `sip_mrcp.` 会出现联想建议。它不是直接交给 TShark 的普通字段过滤器，而是先从 SDP 的 `m=audio` 端口定位 SIP INVITE，再关联同一 Call-ID 的 SIP Dialog、SDP 中的 MRCPv2 `m=application`/`a=channel`、MRCP TCP 流以及 RTP/RTCP UDP 流。结果会以一个完整 ASR 关联视图分页展示；当同一媒体端口匹配多个 Call-ID 时，界面会提示并合并显示。宏也可以嵌入普通 `AND/OR` 表达式，导出时会自动展开并应用对应 Decode As。实现会优先使用磁盘索引，旧索引缺少 SIP 正文索引字段时会回退到 TShark 扫描。

## SIP VoIP 时序图

打开左侧 **SIP 时序图** 后：

- 如果数据包分析区已有已应用过滤器，时序图只绘制过滤结果中的 SIP 会话。
- 如果过滤器为空，会从当前抓包加载全部 SIP 报文，并按 Call-ID 拆分会话。
- 默认只显示通话会话列表，不生成时序图，也不显示逐会话彩色标识块。点击会话行的“时序图”查看单个会话；也可勾选多个会话后点击列表上方的“时序图”，支持合并或按会话分组，并可随时收起。
- 点击时序消息可在下方展开该数据包的 SIP 原始报文；右侧可切换合并时序或按会话分组。
- 大型 TCP/UDP 流需要从数据包右键菜单显式选择“追踪流”，数据包列表不再使用双击触发。

编解码支持范围：

| 编解码              | 动态 PT 映射 | 载荷协议解析                             | 音频播放 / WAV     |
| ------------------- | ------------ | ---------------------------------------- | ------------------ |
| PCMU / PCMA         | 支持         | RTP 字段、原始载荷                       | 支持，8 kHz 单声道 |
| Opus                | 支持         | 调用 TShark Opus 解析器                  | 尚未支持           |
| AMR / AMR-WB        | 支持         | CMR、ToC、帧类型与载荷字段，支持两种封装 | 尚未支持           |
| H.264 / H.265 / VP8 | 支持         | 调用对应 TShark 解析器                   | 尚未提供视频播放   |
| telephone-event     | 支持         | 调用 TShark RTP Event 解析器             | 不适用             |
| G.722 / G.729       | 支持         | 映射信息、RTP 字段与统计                 | 尚未支持           |

映射仅影响该工作台的解析配置，不修改原始 PCAP。导出的 PCAPNG 不嵌入手工映射，其他工具打开时可能仍需重新设置。G.722 的 RTP 时钟频率使用 8000 Hz，区别于解码后的音频采样率。

AMR 载荷封装参数按每条映射保存，不同 SSRC 的同一 PT 可以分别使用 AMR、AMR-WB 及不同封装。参数含义与默认值参考 [RFC 4867](https://www.rfc-editor.org/rfc/rfc4867.html#section-8.3.1)。

## SUSE 与 Node 21 部署

前端构建和服务运行可以分开：在满足 Vite 要求的机器构建 `dist/`，再将构建结果和服务代码复制到 SUSE。Node 21.7.3 已通过本项目的后端解析与 HTTP 接口测试；这是本机兼容性验证，**尚未在 SUSE 实机验证**。SUSE 上还需确认 Node 二进制和 TShark/Lua 能正常运行。

构建机：

```sh
npm ci
npm run build
```

部署时保留 `dist/`、`server/`、`src/packetData.js`、`package.json` 和 `package-lock.json`。其中 `src/packetData.js` 用于生成演示抓包。不要跨系统复制开发机的 `node_modules/`；已有分析数据仅在确实需要迁移时复制。

SUSE 目标目录内执行：

```sh
node --version
tshark --version
npm ci --omit=dev
npm start -- --host 0.0.0.0
```

打开 `http://<SUSE_IP>:3001/`。Node 同时提供 `dist/` 和 API，因此 SUSE 上无需运行 Vite。内网离线安装需事先准备 npm 生产依赖缓存及对应 SUSE/CPU 架构的 TShark 软件包。

配置通过环境变量传入：

| 变量               | 默认值                      | 用途                                 |
| ------------------ | --------------------------- | ------------------------------------ |
| `TSHARK_PATH`      | `tshark`                    | TShark 可执行文件路径                |
| `TSHARK_LUA_SCRIPTS` | `[]` | 自定义 Lua 脚本绝对路径的 JSON 数组，按顺序加载、重复路径去重 |
| `SHARKD_PATH` | 未启用 | 可选 sharkd 可执行文件路径；要求版本与 TShark 一致 |
| `QUERY_CACHE_LIMIT` | `16` | 每个抓包保留的过滤条件数，范围 1–64 |
| `QUERY_CACHE_BYTES` | `268435456` | 每个抓包的基本查询索引缓存预算；至少保留最新一个结果，临时排序文件另计 |
| `HOST`             | `0.0.0.0`                   | 服务监听地址；也可用 `--host` 指定       |
| `PORT`             | `3001`                      | HTTP 端口                            |
| `ALLOWED_HOSTS`    | 绑定地址及本机回环地址      | 允许访问的主机名，逗号分隔、不含端口；使用 `0.0.0.0` 时默认允许 Host，建议显式设置 |
| `DATA_DIR`         | 项目下 `.webshark/`         | 原始抓包、映射配置、索引的存储目录   |
| `MAX_UPLOAD_BYTES` | `1073741824`                | 单文件上传上限，默认 1 GiB           |
| `PARSE_TIMEOUT_MS` | `600000`                    | 单次索引解析超时，默认 10 分钟       |

服务现在默认绑定所有网卡，便于 SUSE 内网访问；由于没有用户认证和用户间数据隔离，生产环境建议指定 `--host` 或配置 `ALLOWED_HOSTS`，并通过带认证的反向代理访问。代理应保留原始 Host；上传大小与代理超时也应相应配置。离线解析不需要网卡捕获权限，服务和 TShark 可使用普通账户运行。

## 自定义 Lua 协议解析

支持 Wireshark Lua dissector、heuristic dissector 和 postdissector。把脚本放在服务端，再启动服务：

```sh
TSHARK_LUA_SCRIPTS='["/opt/webtshark/lua/uap.lua","/opt/webtshark/lua/custom_rtp.lua"]' npm start
```

这些脚本会通过 TShark 的 `-X lua_script:...` 参数加载，覆盖首次解析、后续过滤、详情、追踪及导出路径。字段注册发现兼容 TShark 4.2 的 `-G fields` 参数限制。示例见 [examples/lua/webdemo.lua](examples/lua/webdemo.lua)：在 UDP 19000 上解析一字节消息类型和后续文本，注册 `webdemo.kind` / `webdemo.body`；可过滤 `webdemo.kind == 73`，也可把该字段加入数据包列。业务脚本自行注册端口或启发式解析规则。

在网页的“解析服务状态”或 `/api/health` 中可查看加载的脚本文件名。语法错误、加载错误或缺失路径会导致启动自检失败，并返回具体错误；不会静默忽略。Lua 由服务管理员配置，以服务账户权限执行，应使用可信脚本；网页不提供脚本上传执行入口。

修改脚本及其依赖模块后重启服务。启用自定义 Lua 时，服务重启会重新解析保留的抓包，避免使用旧字段或旧解码结果；脚本内容和引擎版本也写入索引签名。为保留有状态 Lua 的前序报文上下文，自定义 Lua 的详情解析使用完整抓包，且不走 sharkd 快速过滤路径。脚本与 TShark 自身加载的插件一样，需适配安装版本的 Lua API；尽量不要向 stdout 打印调试信息，以免干扰结构化输出。

## 验证

### 过滤性能

普通显示过滤仍由 TShark 判断匹配包。字段已覆盖且解码配置不变时，过滤结果仅保存每个命中包的 16 字节引用（原索引偏移、记录长度、原始包号），不再重复序列化整份协议字段。稀疏匹配按 100 行索引块读取，避免顺序扫描全部 JSONL。分页、诊断、定位及全局排序均支持引用索引；额外 Decode As 或尚未索引的自定义字段仍进行完整提取。LRU 缓存默认保留 16 个条件，并按基本索引字节数控制预算。无 PT 映射时仅注册内部 Lua 字段，不再安装逐包 postdissector。

如已安装同版本 sharkd，可开启常驻过滤：

```sh
SHARKD_PATH=/usr/bin/sharkd npm start
```

当前快路径仅接受单个 `tcp contains "文本"` 或 `tcp contains 00:50` 条件，使用 Wireshark 原生判断，不将它替换成 TCP 重组流搜索。复合条件、应用层/重组字段、自定义 Lua、PT 映射、端口 Decode As、RTP 启发式等继续走 TShark。一个常驻会话最多加载 256 MiB / 50 万包，串行处理请求，空闲 60 秒自动释放；首次查询需要加载文件，切换文件也会重载。版本不一致、进程失败或响应异常时自动回退 TShark。sharkd 仅通过进程 stdin/stdout 通信，不开放独立网络端口。

2026-11-04 本机 TShark 4.2.2 对照测试（相同合成输入、未清空系统文件缓存）：

| 项目 | 优化前 | 优化后 |
| --- | ---: | ---: |
| 201 MiB / 166,000 包，后端首批数据就绪（三次中位数） | 1.78 秒 | 0.13 秒 |
| 同一样本完整索引（三次中位数） | 5.58 秒 | 5.49 秒 |
| 同一样本 `udp` 首次过滤（单次） | 3.80 秒 | 3.23 秒 |
| `udp` 查询索引体积 | 157.11 MiB | 2.53 MiB |
| 34 MiB / 32,000 TCP 包，首次 contains（包括会话加载，单次） | 2.71 秒 | 2.08 秒 |
| 同一会话第二个新的 contains 条件（415 个命中，单次） | 2.59 秒 | 0.30 秒 |
| 同一会话新的无匹配 contains 条件（单次） | 2.56 秒 | 0.16 秒 |

两条 TCP 命中查询的全部包号已与 TShark 路径逐项比较一致。重复查询和翻页仍为毫秒级；引用索引增加一次间接读取，本样本缓存页约 0.6–3.4 ms。首批时间是后端就绪时间，不含上传、网页轮询和网络传输；本轮完整解析耗时没有显著变化。主要收益是提前浏览、降低过滤结果磁盘占用，以及常驻会话中的新 contains 查询。合成样本不能代表真实复杂抓包，常驻引擎额外占用内存。

可复测当前版本大文件索引、首批就绪、过滤和分页：`node scripts/benchmark-large.mjs 200`。可选路径回归使用 `SHARKD_PATH=/usr/bin/sharkd npm test`；不设置时跳过 sharkd 专项测试。

```sh
npm test
npm run build
```

测试直接使用本机 TShark，覆盖真实 PCAP 分页、字段与字节偏移、过滤语法、TCP/UDP 流、PT 映射隔离、Opus 载荷解析、AMR/AMR-WB 两种封装的真实载荷字段、G.711 WAV、丢包补静音、时间戳回绕、PCAPNG 导出、HTTP 上传/错误处理，以及 React 界面与真实 API 的集成。

仅验证旧 Node 的服务运行兼容性时，在该 Node 环境运行：

```sh
node --test test/engine.test.mjs test/http.test.mjs test/amr.test.mjs
```

## 当前限制

- 支持 TShark 能识别的协议，不等于已实现 Wireshark 所有界面与分析功能；TLS 密钥导入/解密、对象导出、完整 RTCP 分析等尚未提供。
- RTP 丢包由抓包中可见的序列号推算，不能区分网络丢失与抓包遗漏；只有已知时钟频率时才显示抖动。动态载荷的人工映射需与实际媒体一致。
- G.711 WAV 最长 10 分钟，依据 RTP 时间戳排列、缺失处补静音；不包含高级抖动缓冲、丢包隐藏或双向混音。波形计算不再静默截断前 10,000 个包，超过 2,400 个显示点时仅对可视波形降采样，并保留原始包数和 RTP 时间轴。
- 每页默认 100 包，也可切换为 200、500、1000；索引写磁盘并缓存过滤结果。首次对大结果集使用非默认排序时，会生成临时磁盘排序索引。默认最多保留 30 个抓包，同时最多 2 个导入任务；超大文件和长期运行的性能仍需专项压测。
- 单次 TShark 文本响应有大小保护；追踪超大的 TCP/UDP 流时需要先用 `tcp.stream`、`udp.stream`、Call-ID 或 ASR/MRCP 端口缩小范围。
- 统计最多保留 10,000 个会话/端点/RTP 分组，专家信息列表展示前 2,000 项；备注保存在当前浏览器，标记仅在当前界面会话内保留。
