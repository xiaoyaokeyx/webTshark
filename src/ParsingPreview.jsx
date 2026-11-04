import React, { useEffect, useState } from "react";
import { api, capturePath } from "./api.js";
import "./parsing-preview.css";

export default function ParsingPreview({ capture, timeFormat, formatTime }) {
  const [page, setPage] = useState(0);
  const [result, setResult] = useState({ packets: [], total: 0 });
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    let timer;
    async function update() {
      try {
        const next = await api(capturePath(capture.id, `/progress-packets?page=${page}`), { signal: controller.signal });
        if (controller.signal.aborted) return;
        setResult(next);
        setError("");
      } catch (e) {
        if (!controller.signal.aborted) setError(e.message);
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(update, 350);
      }
    }
    update();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [capture.id, capture.revision, page]);
  const pages = Math.max(1, Math.ceil(result.total / 100));
  return <section className="parsing-preview" aria-label="解析中的数据包预览">
    <div className="parsing-preview-bar">
      <strong>已就绪 {result.total.toLocaleString()} 包</strong>
      <span>可先翻页浏览；完整过滤和协议详情在解析完成后开放。</span>
      <div className="parsing-preview-pages">
        <button className="button secondary" disabled={!page} onClick={() => setPage(page - 1)} aria-label="预览上一页">上一页</button>
        <span>{page + 1} / {pages}</span>
        <button className="button secondary" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)} aria-label="预览下一页">下一页</button>
      </div>
    </div>
    {error && <p role="alert">{error}</p>}
    <div className="parsing-preview-table">
      <table className="packet-table">
        <thead><tr>{["No.", "时间", "源地址", "目标地址", "协议", "长度", "信息"].map((name) => <th key={name}>{name}</th>)}</tr></thead>
        <tbody>{result.packets.map((p) => <tr key={p.no}>
          <td>{p.no}</td><td>{formatTime(p, timeFormat)}</td><td>{p.source}</td><td>{p.destination}</td><td>{p.protocol}</td><td>{p.length}</td><td title={p.info}>{p.info}</td>
        </tr>)}</tbody>
      </table>
      {!result.packets.length && <p className="parsing-preview-empty">{capture.status === "paused" ? "解析已暂停" : "等待首批数据包…"}</p>}
    </div>
  </section>;
}
