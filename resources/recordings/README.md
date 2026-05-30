# README GIF recordings

The animated GIFs in the project README are generated with
[vhs](https://github.com/charmbracelet/vhs) from the `.tape` scripts here, so
they are fully reproducible.

## Regenerate

```bash
brew install vhs            # needs ttyd + ffmpeg (pulled in as deps)
ollama pull gemma3:1b       # for the SDK demo (any small local model works)

cd resources/recordings
vhs initdev.tape            # -> ../admina-init-dev.gif
vhs sdk.tape                # -> ../sdk-3lines.gif
```

## What each one shows

| Tape | Output | Scene |
|------|--------|-------|
| `initdev.tape` | `admina-init-dev.gif` | `admina init` scaffolds a project, then `admina dev --no-browser` boots the proxy + dashboard to `Ready → localhost:3000` (no Docker). First-boot credentials are masked. |
| `sdk.tape` | `sdk-3lines.gif` | `demo.py` wraps a local model with `GovernedModel`; PERSON / EMAIL / credit-card PII is stripped before the model is called. |

## Notes

- The `admina` shell function defined inside `initdev.tape` masks the generated
  credentials and filters uvicorn access logs so the boot ends cleanly on the
  "Ready" banner — it does not change Admina's behaviour.
- `demo.py` pins `gemma3:1b` and `temperature: 0` for a deterministic, short
  reply. Swap the model for any tag you have pulled.
