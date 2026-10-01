/**
 * Normalize every compiled input the decompiler accepts into script records.
 *
 * Supported compiled forms:
 * - raw Luau bytecode (official or Roblox client)
 * - base64, hex, data-URI wrappers
 * - compiler-error blobs (version byte 0)
 * - Roblox binary models/places (.rbxm / .rbxl), including LZ4 and zstd chunks
 * - Roblox XML models/places (.rbxmx / .rbxlx)
 * - zip archives of the above
 * - JSON batches ({ scripts | files })
 */
const zlib = require("zlib");
const { spawnSync } = require("child_process");

const SCRIPT_CLASSES = new Set(["Script", "LocalScript", "ModuleScript"]);
const SOURCE_PROPS = new Set(["Source", "Bytecode", "ProtectedString"]);

function looksLikeText(buf) {
  if (!buf || buf.length === 0) return false;
  let printable = 0;
  const n = Math.min(buf.length, 256);
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  }
  return printable / n > 0.85;
}

function looksLikeBytecode(buf) {
  if (!buf || buf.length < 3) return false;
  const v = buf[0];
  if (v === 0) return true; // compiler error blob
  if (v >= 1 && v <= 14) return true;
  if (v === 100) return true;
  return false;
}

function looksLikeSource(buf) {
  if (!looksLikeText(buf)) return false;
  const s = buf.slice(0, 80).toString("utf8").trimStart();
  return /^(--|local |function |return |if |for |while |repeat |do |export )/.test(s);
}

function decodeWrapped(text) {
  if (typeof text !== "string") return null;
  let s = text.trim();
  if (!s) return null;
  const dataUri = s.match(/^data:[^,]*;base64,([A-Za-z0-9+/=\s]+)$/i);
  if (dataUri) s = dataUri[1];
  const compact = s.replace(/\s+/g, "");
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length >= 4 && compact.length % 2 === 0) {
    return Buffer.from(compact, "hex");
  }
  if (/^[A-Za-z0-9+/]+=*$/.test(compact) && compact.length >= 4) {
    try {
      const buf = Buffer.from(compact, "base64");
      if (buf.length > 0) return buf;
    } catch (_) {}
  }
  return Buffer.from(s, "utf8");
}

function lz4Decompress(src, uncompressedSize) {
  const out = Buffer.alloc(uncompressedSize);
  let ip = 0;
  let op = 0;
  while (ip < src.length && op < uncompressedSize) {
    const token = src[ip++];
    let litLen = token >> 4;
    if (litLen === 15) {
      let b;
      do {
        if (ip >= src.length) throw new Error("truncated lz4 literal length");
        b = src[ip++];
        litLen += b;
      } while (b === 255);
    }
    if (ip + litLen > src.length) throw new Error("truncated lz4 literals");
    src.copy(out, op, ip, ip + litLen);
    ip += litLen;
    op += litLen;
    if (op >= uncompressedSize) break;
    if (ip + 2 > src.length) throw new Error("truncated lz4 offset");
    const offset = src[ip] | (src[ip + 1] << 8);
    ip += 2;
    if (offset === 0 || offset > op) throw new Error("bad lz4 offset");
    let matchLen = (token & 0x0f) + 4;
    if ((token & 0x0f) === 15) {
      let b;
      do {
        if (ip >= src.length) throw new Error("truncated lz4 match length");
        b = src[ip++];
        matchLen += b;
      } while (b === 255);
    }
    let m = op - offset;
    for (let i = 0; i < matchLen && op < uncompressedSize; i++) out[op++] = out[m++];
  }
  return out;
}

function zstdDecompress(src) {
  const child = spawnSync("zstd", ["-d", "-c"], { input: src, maxBuffer: 64 * 1024 * 1024 });
  if (child.status !== 0) {
    throw new Error((child.stderr && child.stderr.toString()) || "zstd decompress failed");
  }
  return child.stdout;
}

function decompressChunk(raw, compressedLength, uncompressedLength) {
  if (compressedLength === 0) return raw.slice(0, uncompressedLength);
  if (raw.length >= 4 && raw[0] === 0x28 && raw[1] === 0xb5 && raw[2] === 0x2f && raw[3] === 0xfd) {
    return zstdDecompress(raw);
  }
  return lz4Decompress(raw, uncompressedLength);
}

function readString(buf, pos) {
  if (pos + 4 > buf.length) throw new Error("truncated string length");
  const len = buf.readUInt32LE(pos);
  pos += 4;
  if (pos + len > buf.length) throw new Error("truncated string");
  return [buf.slice(pos, pos + len), pos + len];
}

function readInterleavedU32(buf, pos, count) {
  const bytes = count * 4;
  if (pos + bytes > buf.length) throw new Error("truncated interleaved array");
  const out = new Array(count);
  for (let i = 0; i < count; i++) {
    const b0 = buf[pos + i];
    const b1 = buf[pos + count + i];
    const b2 = buf[pos + count * 2 + i];
    const b3 = buf[pos + count * 3 + i];
    out[i] = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
  }
  return out;
}

function parseSstr(data) {
  if (data.length < 8) return [];
  let pos = 4; // version
  const count = data.readUInt32LE(pos);
  pos += 4;
  const strings = [];
  for (let i = 0; i < count; i++) {
    pos += 16; // md5
    const [s, next] = readString(data, pos);
    pos = next;
    strings.push(s);
  }
  return strings;
}

function parseInst(data) {
  let pos = 0;
  const classId = data.readUInt32LE(pos);
  pos += 4;
  const [nameBuf, next] = readString(data, pos);
  pos = next;
  const objectFormat = data[pos];
  pos += 1;
  const count = data.readUInt32LE(pos);
  return { classId, className: nameBuf.toString("utf8"), objectFormat, count };
}

function parseProp(data, classCount, shared) {
  let pos = 0;
  const classId = data.readUInt32LE(pos);
  pos += 4;
  const [nameBuf, next] = readString(data, pos);
  pos = next;
  const typeId = data[pos];
  pos += 1;
  const propName = nameBuf.toString("utf8");
  const count = classCount;
  if (!count || (!SOURCE_PROPS.has(propName) && propName !== "Name")) {
    return null;
  }
  if (typeId === 0x01 || typeId === 0x1d) {
    const values = [];
    for (let i = 0; i < count; i++) {
      const [s, npos] = readString(data, pos);
      pos = npos;
      values.push(s);
    }
    return { classId, propName, values };
  }
  if (typeId === 0x1c && shared) {
    const idxs = readInterleavedU32(data, pos, count);
    return {
      classId,
      propName,
      values: idxs.map((i) => shared[i] || Buffer.alloc(0)),
    };
  }
  return null;
}

function extractBinaryModel(buf) {
  if (buf.length < 32 || buf.slice(0, 8).toString("utf8") !== "<roblox!") return null;
  const classes = new Map();
  const props = [];
  let shared = [];
  let pos = 32;
  while (pos + 16 <= buf.length) {
    const chunkName = buf.slice(pos, pos + 4).toString("utf8").replace(/\0+$/, "");
    const compressedLength = buf.readUInt32LE(pos + 4);
    const uncompressedLength = buf.readUInt32LE(pos + 8);
    pos += 16;
    const dataLen = compressedLength === 0 ? uncompressedLength : compressedLength;
    if (pos + dataLen > buf.length) break;
    const raw = buf.slice(pos, pos + dataLen);
    pos += dataLen;
    let data;
    try {
      data = decompressChunk(raw, compressedLength, uncompressedLength);
    } catch (err) {
      if (chunkName === "END") break;
      continue;
    }
    if (chunkName === "SSTR") shared = parseSstr(data);
    else if (chunkName === "INST") {
      const inst = parseInst(data);
      classes.set(inst.classId, inst);
    } else if (chunkName === "PROP") {
      const cls = classes.get(data.readUInt32LE(0));
      const parsed = parseProp(data, cls ? cls.count : 0, shared);
      if (parsed) props.push(parsed);
    } else if (chunkName === "END") break;
  }

  const byClass = new Map();
  for (const prop of props) {
    if (!byClass.has(prop.classId)) byClass.set(prop.classId, {});
    byClass.get(prop.classId)[prop.propName] = prop.values;
  }
  const scripts = [];
  for (const [classId, bag] of byClass) {
    const cls = classes.get(classId);
    if (!cls || !SCRIPT_CLASSES.has(cls.className)) continue;
    const sources = bag.Source || bag.Bytecode || bag.ProtectedString || [];
    const names = bag.Name || [];
    for (let i = 0; i < sources.length; i++) {
      scripts.push(recordFromBlob(sources[i], names[i] ? names[i].toString("utf8") : `${cls.className}_${i}`, cls.className));
    }
  }
  return { format: "rbx-binary", scripts };
}

function recordFromBlob(blob, name, className) {
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  if (looksLikeBytecode(buf) && !looksLikeSource(buf)) {
    return { name, className: className || null, bytecode: buf, kind: "bytecode" };
  }
  if (looksLikeSource(buf) || looksLikeText(buf)) {
    return { name, className: className || null, source: buf.toString("utf8"), kind: "source" };
  }
  return { name, className: className || null, bytecode: buf, kind: "bytecode" };
}

function extractXmlModel(text) {
  if (!text.includes("<roblox")) return null;
  const scripts = [];
  const itemRe = /<Item\b([^>]*)>/g;
  const items = [];
  let m;
  while ((m = itemRe.exec(text))) {
    const attrs = m[1];
    const classMatch = attrs.match(/class="([^"]+)"/);
    items.push({ index: m.index, className: classMatch ? classMatch[1] : "" });
  }
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!SCRIPT_CLASSES.has(item.className)) continue;
    const end = i + 1 < items.length ? items[i + 1].index : text.length;
    const slice = text.slice(item.index, end);
    const nameMatch = slice.match(/<(?:string|ProtectedString|BinaryString)\b[^>]*name="Name"[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([^<]*))<\/(?:string|ProtectedString|BinaryString)>/);
    const sourceMatch = slice.match(/<(?:string|ProtectedString|BinaryString|Content)\b[^>]*name="(?:Source|Bytecode)"[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([^<]*))<\/(?:string|ProtectedString|BinaryString|Content)>/);
    if (!sourceMatch) continue;
    const name = (nameMatch && (nameMatch[1] || nameMatch[2]) || `${item.className}_${scripts.length}`).trim();
    const raw = sourceMatch[1] != null ? sourceMatch[1] : sourceMatch[2] || "";
    const decoded = decodeWrapped(raw);
    scripts.push(recordFromBlob(decoded || Buffer.from(raw, "utf8"), name, item.className));
  }
  return { format: "rbx-xml", scripts };
}

function extractZip(buf) {
  if (buf.length < 4 || buf.readUInt32LE(0) !== 0x04034b50) return null;
  const scripts = [];
  let pos = 0;
  while (pos + 30 <= buf.length && buf.readUInt32LE(pos) === 0x04034b50) {
    const method = buf.readUInt16LE(pos + 8);
    const compSize = buf.readUInt32LE(pos + 18);
    const nameLen = buf.readUInt16LE(pos + 26);
    const extraLen = buf.readUInt16LE(pos + 28);
    const name = buf.slice(pos + 30, pos + 30 + nameLen).toString("utf8");
    const dataStart = pos + 30 + nameLen + extraLen;
    const comp = buf.slice(dataStart, dataStart + compSize);
    pos = dataStart + compSize;
    if (name.endsWith("/")) continue;
    let data = comp;
    if (method === 8) data = zlib.inflateRawSync(comp);
    else if (method !== 0) continue;
    const nested = collectFromBuffer(data, name);
    for (const s of nested.scripts) {
      scripts.push({ ...s, name: s.name && s.name !== name ? `${name}:${s.name}` : name });
    }
  }
  return { format: "zip", scripts };
}

function collectFromBuffer(buf, filename) {
  if (!buf || buf.length === 0) return { format: "empty", scripts: [] };
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    return collectFromBuffer(zlib.gunzipSync(buf), filename);
  }
  if (buf.slice(0, 8).toString("utf8") === "<roblox!") {
    return extractBinaryModel(buf) || { format: "rbx-binary", scripts: [] };
  }
  const zip = extractZip(buf);
  if (zip && zip.scripts.length) return zip;
  const asText = looksLikeText(buf) ? buf.toString("utf8") : "";
  if (asText.includes("<roblox")) {
    const xml = extractXmlModel(asText);
    if (xml && xml.scripts.length) return xml;
  }
  if (looksLikeBytecode(buf) && !looksLikeSource(buf)) {
    return { format: "luau-bytecode", scripts: [recordFromBlob(buf, filename || "script", null)] };
  }
  if (asText) {
    const wrapped = decodeWrapped(asText);
    if (wrapped && wrapped !== buf && looksLikeBytecode(wrapped) && !looksLikeSource(wrapped)) {
      return { format: "wrapped-bytecode", scripts: [recordFromBlob(wrapped, filename || "script", null)] };
    }
    if (looksLikeSource(buf)) {
      return { format: "lua-source", scripts: [{ name: filename || "script", className: null, source: asText, kind: "source" }] };
    }
  }
  return { format: "unknown", scripts: [recordFromBlob(buf, filename || "script", null)] };
}

function collectFromJson(body) {
  const encoding = body.encoding || body.opcodeEncoding || "auto";
  const list = body.scripts || body.files || null;
  if (Array.isArray(list)) {
    const scripts = [];
    for (const item of list) {
      if (!item || typeof item !== "object") continue;
      const name = item.name || item.path || `script_${scripts.length}`;
      const className = item.className || item.class || null;
      const hint = item.encoding || encoding;
      if (item.source && !item.bytecode && !item.hex && !item.data && !item.b64) {
        scripts.push({ name, className, source: String(item.source), kind: "source", encoding: hint });
        continue;
      }
      const payload = item.bytecode || item.b64 || item.data || item.hex || item.content;
      if (typeof payload === "string") {
        const buf = item.hex ? Buffer.from(String(item.hex).replace(/\s+/g, ""), "hex") : decodeWrapped(payload);
        const rec = recordFromBlob(buf || Buffer.alloc(0), name, className);
        rec.encoding = hint;
        scripts.push(rec);
      }
    }
    return { format: "json-batch", encoding, scripts };
  }
  const payload = body.bytecode || body.b64 || body.data || body.hex;
  if (typeof payload === "string") {
    const buf = body.hex && !body.bytecode ? Buffer.from(String(body.hex).replace(/\s+/g, ""), "hex") : decodeWrapped(payload);
    const rec = recordFromBlob(buf || Buffer.alloc(0), body.name || "script", body.className || null);
    rec.encoding = encoding;
    return { format: rec.kind === "source" ? "lua-source" : "luau-bytecode", encoding, scripts: [rec] };
  }
  return null;
}

function collect(input, contentType) {
  if (Buffer.isBuffer(input)) return collectFromBuffer(input, "upload");
  if (input && typeof input === "object") {
    const fromJson = collectFromJson(input);
    if (fromJson && fromJson.scripts.length) return fromJson;
  }
  if (typeof input === "string") return collectFromBuffer(Buffer.from(input, "utf8"), "body");
  return { format: "empty", scripts: [] };
}

module.exports = {
  collect,
  collectFromBuffer,
  looksLikeBytecode,
  extractBinaryModel,
  extractXmlModel,
  lz4Decompress,
};
