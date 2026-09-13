/**
 * Leo remote decompiler API for Railway.
 * POST /decompile  { "bytecode": "<base64>" }
 * GET  /health
 */
const express = require("express");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const LUAU_BIN = process.env.LUAU_BIN || "luau";
const LEO_CLI = path.join(__dirname, "leo_cli.luau");
const MAX_BODY = 8 * 1024 * 1024;
const TIMEOUT_MS = Number(process.env.DECOMPILE_TIMEOUT_MS || 45000);

app.use(express.json({ limit: MAX_BODY }));
app.use(express.text({ type: "*/*", limit: MAX_BODY }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, luau: LUAU_BIN, cli: fs.existsSync(LEO_CLI) });
});

function runLeo(base64) {
  return new Promise((resolve, reject) => {
    // Luau CLI often has no `io` library, so we embed the payload in a temp script.
    const id = crypto.randomBytes(8).toString("hex");
    const jobPath = path.join(os.tmpdir(), `leo_job_${id}.luau`);

    let leoLib;
    try {
      leoLib = fs.readFileSync(LEO_CLI, "utf8");
    } catch (err) {
      reject(err);
      return;
    }

    // Strip any previous CLI tail after the Leo IIFE so we only keep the library.
    const endMarker = "end)()";
    const endAt = leoLib.lastIndexOf(endMarker);
    if (endAt < 0) {
      reject(new Error("leo_cli.luau missing end)()"));
      return;
    }
    const lib = leoLib.slice(0, endAt + endMarker.length);

    // base64 alphabet cannot contain ]], safe for long strings
    const job = `${lib}

local b64 = [[${base64}]]

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
		out[#out + 1] = string.char(bit32.rshift(n, 16) % 256)
		if n3 then out[#out + 1] = string.char(bit32.rshift(n, 8) % 256) end
		if n4 then out[#out + 1] = string.char(n % 256) end
		i += 4
	end
	return table.concat(out)
end

local ok, raw = pcall(b64decode, b64)
if not ok or type(raw) ~= "string" or raw == "" then
	error("invalid base64: " .. tostring(raw))
end

local ok2, result = pcall(Leo.decompile_bytecode, raw)
if not ok2 then
	error(tostring(result))
end
print(result or "")
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

    child.stdout.on("data", (c) => {
      stdout += c.toString("utf8");
    });
    child.stderr.on("data", (c) => {
      stderr += c.toString("utf8");
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      try { fs.unlinkSync(jobPath); } catch (_) {}
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      try { fs.unlinkSync(jobPath); } catch (_) {}
      if (code === 0) resolve(stdout);
      else reject(new Error(stderr.trim() || `luau exit ${code}`));
    });
  });
}

app.post("/decompile", async (req, res) => {
  try {
    let b64 = null;
    if (req.is("application/json") && req.body && typeof req.body === "object") {
      b64 = req.body.bytecode || req.body.b64 || req.body.data;
    } else if (typeof req.body === "string") {
      b64 = req.body;
    }

    if (!b64 || typeof b64 !== "string") {
      return res.status(400).json({ ok: false, error: "missing bytecode (base64)" });
    }
    b64 = b64.replace(/\s+/g, "");
    if (b64.length < 4) {
      return res.status(400).json({ ok: false, error: "bytecode too short" });
    }

    console.log(`[decompile] b64 length=${b64.length}`);
    const source = await runLeo(b64);
    console.log(`[decompile] ok source length=${(source || "").length}`);
    res.json({ ok: true, source: source || "" });
  } catch (err) {
    console.error("[decompile] fail", err && err.message ? err.message : err);
    res.status(500).json({ ok: false, error: String(err && err.message ? err.message : err) });
  }
});

app.listen(PORT, () => {
  console.log(`Leo decompiler listening on :${PORT}`);
  console.log(`LUAU_BIN=${LUAU_BIN} CLI=${LEO_CLI}`);
});
