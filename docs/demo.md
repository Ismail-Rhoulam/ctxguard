# Demo

Run the safe, deterministic demonstration from the repository root:

```bash
python3 scripts/demo.py
```

The script creates a temporary `.env` containing clearly synthetic values,
simulates Claude Code's `Read` tool input, and passes it to the real plugin hook.
The expected result is `DENIED`; the explanation identifies the sensitive
filename while no raw value is printed. The temporary directory is deleted at
the end of the run.

## Record a terminal GIF later

1. Use a clean terminal with a readable font and no unrelated environment data.
2. Start a recorder such as VHS or asciinema.
3. Run `python3 scripts/demo.py`.
4. Review every frame to confirm it contains no credentials or private paths.
5. Save the approved asset as `docs/assets/ctxguard-demo.gif` and then add the
   visible README reference.

Do not record a demo using a real `.env` file, even if values appear masked.
