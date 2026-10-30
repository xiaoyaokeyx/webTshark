export async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(() => ({ error: "服务返回了无效响应" }));
  if (!res.ok) throw new Error(data.error || `请求失败 (${res.status})`);
  return data;
}
export function uploadCapture(file, onProgress, signal) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/captures");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-File-Name", encodeURIComponent(file.name));
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable)
        onProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      let data;
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        reject(new Error("服务器返回了无效响应"));
        return;
      }
      xhr.status < 300
        ? resolve(data)
        : reject(new Error(data.error || "导入失败"));
    };
    xhr.onerror = () => reject(new Error("无法连接解析服务"));
    xhr.onabort = () => reject(new Error("上传已取消"));
    const abort = () => xhr.abort();
    signal?.addEventListener("abort", abort, { once: true });
    xhr.onloadend = () => signal?.removeEventListener("abort", abort);
    xhr.send(file);
  });
}
export function capturePath(id, part = "") {
  return `/captures/${id}${part}`;
}
export async function downloadResponse(url, name) {
  const res = await fetch(url);
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.error || "导出失败");
  }
  downloadBlob(await res.blob(), name);
}
export function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const sizeLabel = (n) =>
  n >= 1024 ** 3
    ? `${(n / 1024 ** 3).toFixed(2)} GB`
    : n >= 1024 ** 2
      ? `${(n / 1024 ** 2).toFixed(1)} MB`
      : n >= 1024
        ? `${(n / 1024).toFixed(1)} KB`
        : `${n || 0} B`;
export const protocolClass = (p) =>
  (p || "data").toLowerCase().replace(/[^a-z]/g, "");
export function combineFilter(current, condition, operation) {
  if (operation === "exclude") return `!(${condition})`;
  if (operation === "and")
    return current ? `(${current}) && (${condition})` : condition;
  if (operation === "or")
    return current ? `(${current}) || (${condition})` : condition;
  if (operation === "and-not")
    return current ? `(${current}) && !(${condition})` : `!(${condition})`;
  return condition;
}
