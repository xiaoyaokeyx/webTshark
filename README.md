# WebShark · 离线抓包分析工作台

React 网页界面 + Node.js 服务 + 本机 TShark 解析引擎。上传 PCAP/PCAPNG/CAP 后进行离线分析，不提供实时抓包。目前已接入真实数据解析，但尚未覆盖 Wireshark 的全部功能。

## 已实现

- 文件上传、上传进度、解析状态、取消、历史文件管理。原始文件和解析索引保存在服务端。
- 三窗格分析：分页数据包列表、真实协议字段树、HEX/ASCII 字节视图与字段字节定位。
- 使用 TShark 的显示过滤语法，支持字段补全、保存过滤器和错误提示。无效过滤器保留上次有效结果。
- 在数据包单元格或协议字段上右击：应用、排除、AND、OR、AND NOT、仅准备过滤器；也可显式追踪 TCP/UDP 流、标记数据包。数据包单击查看详情，取消双击追踪以避免误触。
- TCP/UDP 双向流内容、方向切换、搜索、HEX 与下载；协议分布、流量时间线、会话、端点、专家信息。
- SIP VoIP 通话时序图：按 Call-ID 分组，支持多会话合并/分组、IP 两端标识、实际时间/相对时间、消息间隔和原始 SIP 报文展开。时序图会沿用当前已应用的过滤器；无过滤器时显示抓包中的全部 SIP 会话。
- `sip_mrcp.port=12345` ASR/MRCP 关联过滤：从 SIP/SDP 音频端口关联 Call-ID、MRCP Channel-ID、MRCP TCP、RTP/RTCP 流；输入 `sip_mrcp` 时提供语法联想。
- RTP 流列表：源/目标地址和端口、SSRC、PT、编解码、包数、估计丢包、重复包、抖动。
- 动态 PT 96–127 映射：设置编解码、RTP 时钟频率和声道；默认限定到单条有方向的 RTP 流，也可应用于当前抓包。同一 PT 的不同流可以使用不同编解码，流级映射优先。
- 将指定 UDP 端口解码为 RTP；可选 RTP 启发式识别。保存映射后重新解析当前文件，失败时恢复上次有效结果。
- 合成演示抓包包含一组可筛选的 SIP 呼叫信令：INVITE、100/180/200 响应、ACK、BYE；INVITE 与 200 OK 使用不同的多媒体 SDP offer/answer，包含 PCMU、AMR/AMR-WB、H.264、VP8、fmtp 和 RTCP 属性。
- SIP 报文比较：在数据包比较模式中选择两个 SIP 报文，可并排比较 SIP 头域和复杂 SDP 会话描述；支持多媒体段、重复属性、动态 PT、rtpmap/fmtp/rtcp-fb 等字段按媒体段和 PT 对齐，差异与缺失字段会高亮显示。
- PCMA/PCMU 音频试听和 WAV 导出；原始/过滤后 PCAPNG 导出；当前页 CSV/JSON 导出；浏览器本地备注。
- 数据包列表支持两行数据包比较；列标题可排序，支持按 Wireshark 常用字段隐藏、删除、添加和调整顺序。
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

在过滤器输入框中可使用 `sip_mrcp.port=12345`（也支持 `==`、`eq`，以及 `media_port`/`rtp_port` 别名）。输入 `sip_mrcp` 或 `sip_mrcp.` 会出现联想建议。它不是直接交给 TShark 的普通字段过滤器，而是先从 SDP 的 `m=audio` 端口定位 SIP INVITE，再关联同一 Call-ID 的 SIP Dialog、SDP 中的 MRCPv2 `m=application`/`a=channel`、MRCP TCP 流以及 RTP/RTCP UDP 流。结果会以一个完整 ASR 关联视图分页展示；当同一媒体端口匹配多个 Call-ID 时，界面会提示并合并显示。当前宏过滤器建议单独使用，普通 Wireshark 表达式仍可继续使用。实现会优先使用磁盘索引，旧索引缺少 SIP 正文索引字段时会回退到 TShark 扫描。

## SIP VoIP 时序图

打开左侧 **SIP 时序图** 后：

- 如果数据包分析区已有已应用过滤器，时序图只绘制过滤结果中的 SIP 会话。
- 如果过滤器为空，时序图会从当前抓包加载全部 SIP 报文，并按 Call-ID 拆分会话。
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
| `HOST`             | `0.0.0.0`                   | 服务监听地址；也可用 `--host` 指定       |
| `PORT`             | `3001`                      | HTTP 端口                            |
| `ALLOWED_HOSTS`    | 绑定地址及本机回环地址      | 允许访问的主机名，逗号分隔、不含端口；使用 `0.0.0.0` 时默认允许 Host，建议显式设置 |
| `DATA_DIR`         | 项目下 `.webshark/`         | 原始抓包、映射配置、索引的存储目录   |
| `MAX_UPLOAD_BYTES` | `1073741824`                | 单文件上传上限，默认 1 GiB           |
| `PARSE_TIMEOUT_MS` | `600000`                    | 单次索引解析超时，默认 10 分钟       |

服务现在默认绑定所有网卡，便于 SUSE 内网访问；由于没有用户认证和用户间数据隔离，生产环境建议指定 `--host` 或配置 `ALLOWED_HOSTS`，并通过带认证的反向代理访问。代理应保留原始 Host；上传大小与代理超时也应相应配置。离线解析不需要网卡捕获权限，服务和 TShark 可使用普通账户运行。

## 验证

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
- G.711 WAV 最长 10 分钟，依据 RTP 时间戳排列、缺失处补静音；不包含高级抖动缓冲、丢包隐藏或双向混音。
- 每页默认 100 包，也可切换为 200、500、1000；索引写磁盘并缓存过滤结果。默认最多保留 30 个抓包，同时最多 2 个导入任务；超大文件和长期运行的性能仍需专项压测。
- 单次 TShark 文本响应有大小保护；追踪超大的 TCP/UDP 流时需要先用 `tcp.stream`、`udp.stream`、Call-ID 或 ASR/MRCP 端口缩小范围。
- 统计最多保留 10,000 个会话/端点/RTP 分组，专家信息列表展示前 2,000 项；备注保存在当前浏览器，标记仅在当前界面会话内保留。
