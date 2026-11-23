/** 使用官网原始 JS/WASM，通过原生 HID 测试板内现有固件，不烧录。
 * --device-path PATH --output NEW.jsonl [--reset] [--run-ms 300]
 * 默认只读版本和寄存器；显式 --run-ms 才运行/暂停。
 * JS 模块下载到独立临时目录，主机只补上相对 fetch 的 URL 基址。
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile, open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createInterface } from "node:readline";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const value = name => { const n = args.indexOf(name); return n < 0 ? undefined : args[n + 1]; };
const devicePath = value("--device-path"), output = value("--output");
const runMs = value("--run-ms") === undefined ? undefined : Number(value("--run-ms"));
if (!devicePath || !output || (runMs !== undefined && (!Number.isInteger(runMs) || runMs < 1 || runMs > 5000))) {
    throw new Error("--device-path PATH --output NEW.jsonl [--reset] [--run-ms 1..5000]");
}
const log = await open(output, "wx");
const started = performance.now();
async function record(kind, fields = {}) {
    const row = {seconds: (performance.now() - started) / 1000, kind, ...fields};
    await log.write(JSON.stringify(row) + "\n");
    console.log(JSON.stringify(row));
}
let child, lines;
try {
    await mkdir(path.join(root, ".cache"), {recursive: true});
    const cache = await mkdtemp(path.join(root, ".cache", "web-protocol-"));
    const base = "https://stcide.stcaimcu.com/";
    const pins = {
        "chunks/chunk-VGV3K7ZW.js": "fd6677ee0345f04a9e5925771fa183082fadc655ca5799236c8fe8bbe9a7853a",
        "chunks/chunk-FDBPC2DQ.js": "acefa782f917d17e154bdee15328f433c2f97f2166f331302b2a85ac20e1171f",
        "sim_core.wasm": "99dde35ecc2329aaf782641b93c1f393fb9b972250400cf5ea539f21a64e64e2",
    };
    let verifiedWasm;
    for (const name of ["chunks/chunk-VGV3K7ZW.js", "chunks/chunk-FDBPC2DQ.js", "sim_core.wasm"]) {
        const response = await fetch(new URL(name, base));
        if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
        const bytes = Buffer.from(await response.arrayBuffer());
        const sha256 = createHash("sha256").update(bytes).digest("hex");
        if (pins[name] && pins[name] !== sha256) throw new Error(`${name}: website source changed`);
        await mkdir(path.dirname(path.join(cache, name)), {recursive: true});
        await writeFile(path.join(cache, name), bytes);
        await record("SOURCE", {name, sha256, bytes: bytes.length});
        if (name.endsWith(".wasm")) {
            verifiedWasm = bytes;
            const imports = WebAssembly.Module.imports(await WebAssembly.compile(bytes));
            if (imports.length) throw new Error("Unexpected WASM imports");
        }
    }
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (url, init) => {
        const resolved = new URL(url, base);
        if (resolved.href === new URL("sim_core.wasm", base).href) {
            return Promise.resolve(new Response(verifiedWasm));
        }
        return originalFetch(resolved, init);
    };
    // 原网页导出的 buildFrame / exchangeFrame / parseReply，源码保持原样。
    const web = await import(pathToFileURL(path.join(cache, "chunks/chunk-FDBPC2DQ.js")));
    child = spawn(path.join(root, ".venv/Scripts/python.exe"), ["-u",
        path.join(root, "tools/diagnostics/web_sim_transport.py"), "--device-path", devicePath],
        {cwd: root, env: {...process.env, PYTHONUTF8: "1"}, stdio: ["pipe", "pipe", "pipe"]});
    child.stderr.on("data", data => console.error(data.toString()));
    lines = createInterface({input: child.stdout})[Symbol.asyncIterator]();
    const transport = {
        async exchange(packet, timeout) {
            const hex = Buffer.from(packet).toString("hex");
            await record("OUT", {hex, timeout});
            child.stdin.write(JSON.stringify({op: "exchange", hex, timeout}) + "\n");
            let timer;
            const next = await Promise.race([lines.next(), new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error("HID bridge deadline")), 8000);
            })]).finally(() => clearTimeout(timer));
            if (next.done) throw new Error("HID bridge exited");
            const result = JSON.parse(next.value);
            if (!result.ok) { await record("IO_ERROR", result); throw new Error(result.error); }
            await record("IN", {hex: result.hex});
            return Uint8Array.from(Buffer.from(result.hex, "hex"));
        }
    };
    async function request(request) {
        await record("REQUEST", request);
        const result = await web.z(transport, request, "usb", 1000);
        if (!result.ok) throw new Error(`Web protocol rejected reply: ${result.error}`);
        await record("REPLY", {replyKind: result.kind, status: result.status,
            data: Buffer.from(result.data).toString("hex"), pc: result.registers?.pc});
        return result;
    }
    await web.p(transport, 1000);
    if (args.includes("--reset")) {
        await request({what: "reset"});
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    await request({what: "registers"});
    if (runMs !== undefined) {
        await request({what: "run", mode: "full"});
        await new Promise(resolve => setTimeout(resolve, runMs));
        await request({what: "pause"});
        await request({what: "registers"});
    }
    await record("PASS");
} catch (error) {
    await record("FAIL", {error: String(error.stack ?? error)});
    process.exitCode = 1;
} finally {
    if (child) {
        child.stdin.end();
        const exited = new Promise(resolve => child.once("exit", resolve));
        const kill = setTimeout(() => child.kill(), 1500);
        if (child.exitCode === null && child.signalCode === null) await exited;
        clearTimeout(kill);
    }
    await log.close();
}
