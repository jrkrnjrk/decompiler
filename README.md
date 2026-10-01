# Leo remote decompiler (Railway)

Decompiles compiled Luau, not just a single base64 bytecode string.

Handled compiled forms:

- Official Luau bytecode, versions 1–14 and experimental class bytecode 100 (vanilla opcodes)
- Roblox client bytecode (opcode byte decoded with `* 203 % 256`), auto-detected
- Compiler-error blobs (version byte `0`)
- Wrappers: base64, hex, `data:` URIs, raw `application/octet-stream`
- Roblox binary models and places (`.rbxm`, `.rbxl`), LZ4 or zstd chunks, `Source` and `Bytecode` properties
- Roblox XML models and places (`.rbxmx`, `.rbxlx`)
- Zip archives of any of the above
- JSON batches

Script classes pulled out of a model or place: `Script`, `LocalScript`, `ModuleScript`. Source that is already text is returned as-is; bytecode is decompiled. If the lifter cannot rebuild a proto, the response falls back to a disassembly.

## Deploy

1. Push this folder to a GitHub repo (or deploy from Railway CLI).
2. New Railway project → Deploy from that repo.
3. Railway builds the Dockerfile (Luau + zstd + Node API).
4. Copy the public URL, e.g. `https://your-app.up.railway.app`.

### Health check

```bash
curl https://your-app.up.railway.app/health
```

### Bytecode (legacy, still works)

```bash
curl -X POST https://your-app.up.railway.app/decompile \
  -H "Content-Type: application/json" \
  -d '{"bytecode":"BASE64_BYTECODE_HERE"}'
```

Force an opcode encoding with `"encoding": "roblox"` or `"encoding": "vanilla"`. Default is `"auto"`.

### Raw compiled file, model, or place

```bash
curl -X POST https://your-app.up.railway.app/decompile \
  -H "Content-Type: application/octet-stream" \
  --data-binary @script.luac

curl -X POST https://your-app.up.railway.app/decompile \
  -H "Content-Type: application/octet-stream" \
  --data-binary @place.rbxl
```

### Batch

```bash
curl -X POST https://your-app.up.railway.app/decompile \
  -H "Content-Type: application/json" \
  -d '{"scripts":[{"name":"A","bytecode":"..."},{"name":"B","hex":"0500..."}]}'
```

A single script still returns `source` at the top level. Multiple scripts also return `scripts[]` and a combined `source`.

## Wire the client

In `xxleo_saveinstance_stable.luau` set:

```lua
local REMOTE_DECOMPILE_URL = "https://your-app.up.railway.app/decompile"
```

## Notes

- Timeout default: 45s (`DECOMPILE_TIMEOUT_MS`).
- Body limit: 32 MB (`MAX_BODY_BYTES`).
- Executor must support `request` / `syn.request` / `http_request` and `getscriptbytecode`.
