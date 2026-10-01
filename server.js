/**
 * Leo remote decompiler API.
 * Decompiles compiled Luau bytecode and every container that carries it:
 * raw / base64 / hex blobs, Roblox client bytecode, official Luau bytecode,
 * .rbxm/.rbxl/.rbxmx/.rbxlx, and zip batches.
 *
 * POST /decompile   { "bytecode": "<base64>" }   (legacy)
 * POST /decompile   raw bytes, hex, data-URI, model/place, or { scripts: [...] }
 * GET  /health
 * GET  /formats
 */
const express = require("express");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const formats = require("./formats");

const app = express();
const PORT = process.env.PORT || 3000;
const LUAU_BIN = process.env.LUAU_BIN || "luau";
const LEO_CLI = path.join(__dirname, "leo_cli.luau");
const MAX_BODY = Number(process.env.MAX_BODY_BYTES || 32 * 1024 * 1024);
const TIMEOUT_MS = Number(process.env.DECOMPILE_TIMEOUT_MS || 45000);
const cache = new Map();
const CACHE_MAX = 500;

const SUPPORTED = [
  "luau-bytecode (official, vanilla opcodes, v1-v14 and v100)",
  "roblox-client-bytecode (opcode * 203 % 256, auto-detected)",
  "compiler-error blob (version byte 0)",
  "base64, hex, and data-URI wrappers",
  "rbxm / rbxl binary models and places (LZ4 and zstd chunks, Bytecode + Source)",
  "rbxmx / rbxlx XML models and places",
  "zip of any of the above",
  "json batch: { scripts: [{ name, bytecode|hex|source }] }",
];

app.use(express.json({ limit: MAX_BODY }));
app.use(express.raw({ type: ["application/octet-stream", "application/zip", "application/x-rbxm", "application/x-rbxl"], limit: MAX_BODY }));
app.use(express.text({ type: ["text/*", "application/xml", "application/x-lua"], limit: MAX_BODY }));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    version: "2.0.1",
    luau: LUAU_BIN,
    cli: fs.existsSync(LEO_CLI),
    formats: SUPPORTED,
  });
});

app.get("/formats", (_req, res) => {
  res.json({ ok: true, formats: SUPPORTED });
});

function runLeo(buffer, encoding) {
  return new Promise((resolve, reject) => {
    const id = crypto.randomBytes(8).toString("hex");
    const jobPath = path.join(os.tmpdir(), `leo_job_${id}.luau`);
    const b64 = buffer.toString("base64");
    const hint = encoding === "vanilla" || encoding === "roblox" ? encoding : "auto";

    let leoLib;
    try {
      leoLib = fs.readFileSync(LEO_CLI, "utf8");
    } catch (err) {
      reject(err);
      return;
    }
    const endMarker = "end)()";
    const endAt = leoLib.lastIndexOf(endMarker);
    if (endAt < 0) {
      reject(new Error("leo_cli.luau missing end)()"));
      return;
    }
    const lib = leoLib.slice(0, endAt + endMarker.length);
    const job = `${lib}

local b64 = [[${b64}]]
local encoding = "${hint}"

local function b64decode(data)
	local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	data = string.gsub(data or "", "[^" .. alphabet .. "=]", "")
	local out = {}
	local i = 1
	while i <= #data do
		local function val(ch)
			if ch == "=" or ch == "" then return nil end
			local p = string.find(alphabet, ch, 1, true)
			if not p then error("bad b64 char") end
			return p - 1
		end
		local c1 = string.sub(data, i, i)
		local c2 = string.sub(data, i + 1, i + 1)
		local c3 = string.sub(data, i + 2, i + 2)
		local c4 = string.sub(data, i + 3, i + 3)
		local n1, n2, n3, n4 = val(c1), val(c2), val(c3), val(c4)
		if not n1 or not n2 then break end
		local n = n1 * 262144 + n2 * 4096 + (n3 or 0) * 64 + (n4 or 0)
		out[#out + 1] = string.char(math.floor(n / 65536) % 256)
		if n3 then out[#out + 1] = string.char(math.floor(n / 256) % 256) end
		if n4 then out[#out + 1] = string.char(n % 256) end
		i += 4
	end
	return table.concat(out)
end

local raw = b64decode(b64)
local source, meta = Leo.decompile_bytecode(raw, encoding)
meta = meta or {}
print(string.format(
	"@@LEO@@%s|%s|%s|%s",
	tostring(meta.kind or ""),
	tostring(meta.version or ""),
	tostring(meta.encoding or ""),
	tostring(meta.protos or 0)
))
print(source or "")
`;

    try {
      fs.writeFileSync(jobPath, job, "utf8");
    } catch (err) {
      reject(err);
      return;
    }

    const child = spawn(LUAU_BIN, [jobPath], {
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      try { fs.unlinkSync(jobPath); } catch (_) {}
      reject(new Error("decompile timeout"));
    }, TIMEOUT_MS);

    child.stdout.on("data", (c) => { stdout += c.toString("utf8"); });
    child.stderr.on("data", (c) => { stderr += c.toString("utf8"); });
    child.on("error", (err) => {
      clearTimeout(timer);
      try { fs.unlinkSync(jobPath); } catch (_) {}
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      try { fs.unlinkSync(jobPath); } catch (_) {}
      if (code !== 0) {
        const detail = [stderr.trim(), stdout.trim()].filter(Boolean).join("\n");
        reject(new Error(detail || `luau exit ${code}`));
        return;
      }
      const lines = stdout.split(/\r?\n/);
      let meta = null;
      if (lines[0] && lines[0].startsWith("@@LEO@@")) {
        const parts = lines.shift().slice("@@LEO@@".length).split("|");
        meta = { kind: parts[0], version: Number(parts[1]), encoding: parts[2], protos: Number(parts[3]) };
      }
      resolve({ source: lines.join("\n"), meta });
    });
  });
}

async function decompileOne(script) {
  if (script.kind === "source" && script.source != null) {
    return {
      name: script.name,
      className: script.className,
      ok: true,
      kind: "source",
      source: script.source,
      note: "already source, not compiled bytecode",
    };
  }
  const buf = script.bytecode;
  if (!buf || !buf.length) {
    return { name: script.name, className: script.className, ok: false, error: "empty bytecode" };
  }
  const key = `${script.encoding || "auto"}:${buf.toString("base64")}`;
  if (cache.has(key)) {
    return { name: script.name, className: script.className, ok: true, cached: true, ...cache.get(key) };
  }
  const result = await runLeo(buf, script.encoding || "auto");
  const record = {
    source: result.source || "",
    kind: result.meta && result.meta.kind,
    version: result.meta && result.meta.version,
    encoding: result.meta && result.meta.encoding,
    protos: result.meta && result.meta.protos,
  };
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(key, record);
  return { name: script.name, className: script.className, ok: true, ...record };
}

app.post("/decompile", async (req, res) => {
  try {
    const collected = formats.collect(req.body, req.headers["content-type"] || "");
    if (!collected.scripts.length) {
      return res.status(400).json({
        ok: false,
        error: "no compiled scripts found (bytecode, hex, model, place, or scripts[] expected)",
        format: collected.format,
      });
    }
    const scripts = [];
    for (const script of collected.scripts) {
      try {
        scripts.push(await decompileOne(script));
      } catch (err) {
        scripts.push({
          name: script.name,
          className: script.className,
          ok: false,
          error: String(err && err.message ? err.message : err),
        });
      }
    }
    const okCount = scripts.filter((s) => s.ok).length;
    const combined = scripts.map((s) => {
      const header = `-- ${s.className ? s.className + " " : ""}${s.name || "script"}`;
      return `${header}\n${s.ok ? s.source || "" : "-- error: " + s.error}`;
    }).join("\n\n");
    const single = scripts.length === 1 ? scripts[0] : null;
    res.status(okCount ? 200 : 500).json({
      ok: okCount > 0,
      format: collected.format,
      count: scripts.length,
      source: single ? single.source || "" : combined,
      version: single && single.version,
      encoding: single && single.encoding,
      kind: single && single.kind,
      cached: single ? !!single.cached : undefined,
      scripts,
    });
  } catch (err) {
    console.error("[decompile] fail", err && err.message ? err.message : err);
    res.status(500).json({ ok: false, error: String(err && err.message ? err.message : err) });
  }
});

app.listen(PORT, () => {
  console.log(`Leo decompiler listening on :${PORT}`);
  console.log(`LUAU_BIN=${LUAU_BIN} CLI=${LEO_CLI}`);
});
