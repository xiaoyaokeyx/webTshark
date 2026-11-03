# WebTshark 0.3 功能增强与验收

本版本是单用户离线分析工作台，不含用户、账号或租户隔离。

## 新增功能入口

| 需求           | 本版行为                                                                                                                                                       |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 浏览器式标签页 | 抓包、收藏视图分别打开；保留各自过滤器、分页、选包、标记和视图；关闭后选择其他标签；支持重新打开                                                               |
| 任务中心       | 上传/排队/解析/暂停/完成/失败/取消；查看日志、已完成索引段；Linux/macOS 暂停继续、取消、重试；服务重启后恢复完成结果，未完成任务可重试                         |
| 报文构造       | SIP、SDP、RTP、RTCP、MRCPv2；IPv4 地址/端口、包数/间隔、Call-ID/Channel-ID、PT/SSRC/序列号/时钟和正文；自动计算长度与校验和；浏览器直接生成 PCAP，无需解析服务 |
| 过滤历史       | 最近 50 条、撤销/恢复、选取历史；保留原有字段补全/收藏/模板；准备过滤器支持选中、非选中、AND、OR、AND NOT                                                      |
| 导航与搜索     | 当前页前后包；跨页按包号/相对时间跳转；字段文本搜索/异常包定位；详情树包内字段搜索                                                                             |
| 批量收藏       | 标记本页、指定包号范围、清除标记；把标记集合保存为独立收藏标签；已有保存视图可收藏整个过滤结果                                                                 |
| SIP 诊断       | 重复请求、未见最终响应、INVITE 2xx 后未见 ACK、错误响应、缺失 From tag；每条发现带证据包号                                                                     |
| SDP 诊断       | 媒体段共同 PT、PT 编解码冲突、保持/inactive、方向/ptime/fmtp 差异                                                                                              |
| RTP/RTCP       | 原有最终丢包/乱序/重复/抖动；新增到达间隔时间线、观测突发缺口、端点时钟漂移估算、单向流提示、RTCP SSRC/丢包/抖动关联                                           |
| MRCPv2         | Channel-Identifier / Request-ID 配对；方法、首响应耗时、完成事件/原因、窗口内未完成提示；根据 SDP channel 关联 SIP Call-ID                                     |
| PCAP 对比      | 按 Call-ID/CSeq/状态码、五元组、SSRC/序列号/时间戳及相对时间容差匹配；显示差异/单边包，导出 JSON                                                               |
| 报告           | HTML/JSON；HTML 含 SIP SVG 时序图、原始 SIP、SDP、RTP/RTCP 与 MRCP；浏览器打印为 PDF；诊断证据包 PCAPNG 导出                                                   |
| 自动化         | REST API + scripts/analyze.mjs 上传、等待解析、保存报告                                                                                                        |

## 大文件实现边界

TShark 保持单条有状态解码流，保留 TCP 重组、SIP/SDP 和 RTP 关联上下文。Node 流式写磁盘 JSONL 索引，每约 50 MiB 的索引输出形成一个逻辑分段，记录字节范围及包号。完成的分段可以在任务中心提前分页预览。完整解析后统一使用全局索引过滤、排序与分页；点击包时按需解析协议树。前端不加载全量包对象。

这是**流式分段索引**，不是把原始 200 MB PCAP 切成 4 个 50 MB 独立 TShark 进程。后者跨段 TCP/SIP/SDP 可能丢上下文，本版未提供这种不保证等价的默认模式。暂停/继续保留当前进程；取消、崩溃或服务重启后，重试从原文件重新扫描，不是跨进程断点续解析。分段阈值针对索引输出大小，不是原始抓包大小。

200 MiB 规模实测（本环境 TShark 4.2.2 / Node 24）：

| 指标          | 结果                                    |
| ------------- | --------------------------------------- |
| 合成输入      | 210,820,024 字节，166,000 个重复 RTP 包 |
| 全量索引      | 8.49 秒                                 |
| 索引输出      | 164,737,302 字节，4 个逻辑段            |
| 最后一页读取  | 1.21 ms，100 包                         |
| Node 峰值 RSS | 272,375,808 字节（约 260 MiB）          |

仅代表此重复合成 RTP 样本，不代表复杂 SIP/TCP；RSS 不含 TShark 子进程。可复现：`node scripts/benchmark-large.mjs 200`。

## 部署

```sh
npm ci
npm run build
TSHARK_PATH=/opt/wireshark/bin/tshark npm start -- --host 0.0.0.0
```

完整后端要求 Node 20.19+ 或 22.12+、TShark 及 Lua。优先使用普通账户运行。Root 部署必须确认全局 Lua 配置允许 `-X lua_script`；启动时会使用空 PCAP 自检 `webshark.rtp.codec` 注册，失败则 health.ready=false 并提供错误原因。本版不自动覆盖目标机器的全局 Wireshark 配置。

静态预览站点只能运行前端及浏览器内构造/下载。TShark 需要本机进程，无法在静态站点或 Cloudflare Worker 直接运行。完整解析/任务/诊断/报告必须使用上述 Node 服务。静态构建使用 `VITE_STATIC_PREVIEW=1 npm run build`，避免把预览误认为可解析服务。

配置：`JOB_CONCURRENCY` 默认 2（1–3）；`INDEX_SEGMENT_BYTES` 默认 50 MiB；沿用 `DATA_DIR`、`PARSE_TIMEOUT_MS`、`MAX_UPLOAD_BYTES`。暂停不消耗解析超时预算。

## 自动化接口

- `GET /api/tasks`：任务与日志。
- `POST /api/captures/:id/pause|resume|cancel|retry`：任务控制。
- `GET /api/captures/:id/progress-packets?page=0`：已完成分段，每页 100 包。
- `POST /api/compose`：JSON 参数与构造器一致，返回 PCAP；合成文件保护上限 32 MiB。
- `GET /api/captures/:id/diagnostics?filter=sip`：规则诊断 JSON。
- `GET /api/captures/:id/report?format=html`：报告，默认 JSON。
- `POST /api/compare`：`{"a":"capture-id","b":"capture-id","mode":"call","toleranceMs":100}`。
- `GET /api/captures/:id/locate?mode=number&no=150&size=100`。

```sh
node scripts/analyze.mjs capture.pcap report.html http://127.0.0.1:3001
node scripts/analyze.mjs capture.pcap report.json http://127.0.0.1:3001
```

## 诊断与容量限制

“抓包窗口内未见”不是“对端没有发送”的确定结论。SDP 地址与实际媒体不一致时，仅在唯一 SIP Dialog 条件下允许端口/时间候选关联，并明确提示需要核查 NAT/抓包位置。

RTP 突发缺口按到达顺序记录，可能被后续乱序包补齐，最终丢包仍以序列跟踪统计为准。时钟漂移只是首尾估算。RTCP 默认提取首个报告块；报告限定 2,000 条发现/消息，SIP 图最多 8 个端点、100 条消息；PCAP 对比最多索引 A 的 100,000 个候选包并显示 1,000 个差异，达到上限返回 truncated，建议先缩小抓包。PDF 通过 HTML 的打印按钮生成，不是后端二进制 PDF 接口。

TShark 4.2 对 AMR 原生语音帧字段覆盖不完整，但映射保留精确载荷及原生 CMR/ToC。本版修复旧版本 AMR preference 枚举名：使用 `RFC 3267 Byte aligned` / `RFC 3267 Bandwidth-efficient`。

## 验证

排版调整与逐页验收见 [LAYOUT_REVIEW.md](LAYOUT_REVIEW.md)：数据包工具分组、宽表局部滚动、窄屏单列表单，以及构造/任务/诊断/对比弹窗的宽度和高度约束。

运行 `npm test` 覆盖原有协议解析及本版构造校验和、MRCP 长度、任务控制、诊断、对比、报告、标签隔离、收藏与关闭重开；`npm run build` 验证前端构建。新增测试使用真实 TShark，不以固定响应替代解析。

2026-11-03 本环境验证结果：40 项全部通过，0 失败；前端生产构建通过。五种构造模板另由真实 TShark 验证协议字段。
