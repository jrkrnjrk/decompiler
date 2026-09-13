# Leo remote decompiler (Railway)

Runs the Leo Luau decompiler on Railway so your Roblox executor only grabs bytecode and does not crash on full saves.

## Deploy

1. Push this folder to a GitHub repo (or deploy from Railway CLI).
2. New Railway project → Deploy from that repo.
3. Railway will build the Dockerfile (installs Luau + Node API).
4. Copy your public URL, e.g. `https://your-app.up.railway.app`.

### Health check

```bash
curl https://your-app.up.railway.app/health
```

### Test decompile

```bash
curl -X POST https://your-app.up.railway.app/decompile \
  -H "Content-Type: application/json" \
  -d '{"bytecode":"BASE64_BYTECODE_HERE"}'
```

Response:

```json
{ "ok": true, "source": "-- decompiled luau..." }
```

## Wire the client

In `xxleo_saveinstance_stable.luau` set:

```lua
local REMOTE_DECOMPILE_URL = "https://your-app.up.railway.app/decompile"
```

Then run the script as usual. Scripts stay enabled; decompile work is remote.

## Notes

- Timeout default: 45s (`DECOMPILE_TIMEOUT_MS`).
- Body limit: 8 MB base64.
- Executor must support `request` / `syn.request` / `http_request` and `getscriptbytecode`.
