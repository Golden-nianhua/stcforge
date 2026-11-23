# MCS-251 UART monitor

The UART backend attaches to an already enabled monitor on a supported
MCS-251 part, such as STC32G12K128. STC32G144K246 supports UART ISP but does
not offer this monitor. This backend does not implement the MCS-51 register ABI,
UART ISP, or automatic firmware upload. For debug launches, use the original
24-bit MCS-251 HEX of the program currently on the target.

```powershell
uv sync --extra usb --extra uart
uv run --no-sync stcforge uart-probe --serial-port COM7 --serial-baud 115200
uv run --no-sync stcforge gdbserver --uart --serial-port COM7 --image firmware.hex --once
```

For a CLion project, set `model`, `simulation_mode = "uart"`, `uart_port`, and
optionally `uart_baud` in the `[stcforge]` table. The independent
`[simulation_isp]` table controls how `stc-isp` creates the monitor; its `port`
is the ISP port, not the debug port. `--make-simulation` can erase the
program, so prepare the matching user firmware before starting GDB.

## Evidence

Offline disassembly of the installed `C251/BIN/STCMON251.DLL`, SHA-256
`d9e71ce4b48e87e9c6852be1034c29485c0c7e6c8ca823e29bba8e41c4412aa8`.
Addresses below are RVAs from image base `10000000`.

| RVA | UART path |
| --- | --- |
| `184A`, `1A9C` | Nonzero configured COM index other than `100` selects mode 1. Opens COM with caller baud, 8 bits, no parity, two stop bits. |
| `4576`, `1CCA`, `2A5F` | Connect opens port, handshakes with `80` probes, verifies `00 FF` or `FF 00`, then queries version. |
| `22F1–2392` | Write only the meaningful bytes of `FF 5A LEN CMD … CS` to COM. Same negative sum as USB, no report ID or padding. |
| `23E4–24CC`, `2B81` | Expects precisely 7 bytes for an event (`06 00` + four content bytes + `04`) or `N+2` for a data reply (`02 … CS`). No HID length prefix. Full register snapshot is 46 payload bytes. |
| `1F80–1F95`, `1DC9–1E06`, `49EC–4A27` | Pause writes raw `FF`; the run path detects an incoming byte, clears line input, then handshakes again. A single byte alone does not prove a stop. STCForge additionally requires a valid register snapshot. |
| `2DE0–2E50`, `2EA7` | Single-step shares the Keil four-byte instruction-window command. Continue sends `08 00` and reads an event before the stop wait. |

The DLL path is distinct from AiCube's UART ISP path. Offline tests exercise
handshake, split replies, snapshots, read and write framing, continue, stop
confirmation and single-step. No matching UART-monitor board has been used to
validate electrical timing, breakpoint handling or firmware-specific responses.

`C51/BIN/STCMON51.DLL` (SHA-256
`92f948b98aadcf55fd92fdf20955f5cc9e37ef391f10844388274c2d26c56917`) confirms
8N2 at RVA `1B5F–1B70`, raw `FF` pause at `1EE4–1EF4`, and the same
un-padded `FF 5A` request envelope at `1EFF–1FA9`. This is evidence for sharing
the UART link, not for using the 251 target: for example, the C51 register
write path at `309B–30CC` uses PSW register-bank bits to select the R0/R1
addresses. This turn does not add a C51 target description or change the GDB
client's architecture.
