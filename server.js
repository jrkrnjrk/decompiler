/**
 * Leo remote decompiler API for Railway.
 *
 * POST /decompile
 *   body: { "bytecode": "<base64 string>" }  OR raw base64 text/plain
 *   returns: { "ok": true, "source": "..." } | { "ok": false, "error": "..." }
 *
 * GET /health -> { ok: true }
 */
const express = require("express");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const LUAU_BIN = process.env.LUAU_BIN || "luau";
const LEO_CLI = path.join(__dirname, "leo_cli.luau");
const MAX_BODY = 8 * 1024 * 1024; // 8 MB
const TIMEOUT_MS = Number(process.env.DECOMPILE_TIMEOUT_MS || 45000);

app.use(express.json({ limit: MAX_BODY }));
app.use(express.text({ type: "*/*", limit: MAX_BODY }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, luau: LUAU_BIN, cli: fs.existsSync(LEO_CLI) });
});

function runLeo(base64) {
  return new Promise((resolve, reject) => {
    const child = spawn(LUAU_BIN, [LEO_CLI, base64], {
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
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
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
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

    const source = await runLeo(b64);
    res.json({ ok: true, source: source || "" });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err && err.message ? err.message : err) });
  }
});

app.listen(PORT, () => {
  console.log(`Leo decompiler listening on :${PORT}`);
  console.log(`LUAU_BIN=${LUAU_BIN} CLI=${LEO_CLI}`);
});
