"""Lifecycle of one disposable browser sandbox.

Per scan we create:
  * cc-net-<id>    an *internal* Docker network (no route to the internet)
  * cc-proxy-<id>  the egress guard: the only container on that network that
                   is also attached to the outside world
  * cc-sbx-<id>    the browser: read-only root, no capabilities, no host
                   mounts, no secrets, memory/CPU/PID caps, optional gVisor

The orchestrator talks to the browser over stdin/stdout only. Afterwards all
three are destroyed and the teardown is verified.
"""

import asyncio
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROXY_DIR = ROOT / "proxy"

SANDBOX_IMAGE = os.environ.get("CC_SANDBOX_IMAGE", "consentcheck-sandbox:latest")
PROXY_IMAGE = os.environ.get("CC_PROXY_IMAGE", "mitmproxy/mitmproxy:11.0.2")
RUNTIME = os.environ.get("CC_SANDBOX_RUNTIME", "runc")  # "runsc" = gVisor on the Vultr VM
SELF_HOSTS = os.environ.get("CC_SELF_HOSTS", "")  # the VM's public IP and hostname
MEMORY = os.environ.get("CC_SANDBOX_MEMORY", "1g")
CPUS = os.environ.get("CC_SANDBOX_CPUS", "1")
PIDS = os.environ.get("CC_SANDBOX_PIDS", "512")
STEP_TIMEOUT = float(os.environ.get("CC_STEP_TIMEOUT", "60"))
GUARD_DNS = os.environ.get("CC_GUARD_DNS", "1.1.1.1 8.8.8.8").split()


class SandboxDied(Exception):
    def __init__(self, exit_code, stderr_tail=""):
        self.exit_code = exit_code
        self.stderr_tail = stderr_tail
        super().__init__(f"sandbox exited with code {exit_code}")


async def _run(*args, check=True, timeout=60):
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {err.decode()[-300:]}")
    return proc.returncode, out.decode(), err.decode()


class Sandbox:
    def __init__(self, scan_id: str, evidence_dir: Path):
        self.id = scan_id
        self.evidence_dir = evidence_dir
        self.net = f"cc-net-{scan_id}"
        self.proxy = f"cc-proxy-{scan_id}"
        self.sbx = f"cc-sbx-{scan_id}"
        self.proc = None
        self.stderr_tail = b""

    @property
    def profile(self) -> dict:
        """What the report shows as the enforced isolation profile."""
        return {
            "runtime": RUNTIME,
            "network": "internal-only Docker network; single egress via logging guard proxy",
            "egress_blocked": "private, loopback, link-local (cloud metadata) and reserved IPs",
            "filesystem": "read-only root, tmpfs scratch, no host mounts",
            "privileges": "non-root user, all Linux capabilities dropped, no-new-privileges",
            "limits": f"memory {MEMORY} (no swap), {CPUS} CPU, {PIDS} processes, per-step timeout {int(STEP_TIMEOUT)}s",
            "secrets": "none: model API keys stay in the orchestrator",
            "lifecycle": "created for this scan, destroyed afterwards",
        }

    async def start(self):
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # The guard (uid "mitmproxy") may only write into its own sub-directory;
        # the orchestrator copies the log out after the scan without following links.
        guard_dir = self.evidence_dir / "guard"
        guard_dir.mkdir(exist_ok=True)
        log_file = guard_dir / "proxy_log.jsonl"
        log_file.touch()
        os.chmod(guard_dir, 0o777)
        os.chmod(log_file, 0o666)
        await _run("docker", "network", "create", "--internal", self.net)
        runtime = ["--runtime", RUNTIME] if RUNTIME and RUNTIME != "runc" else []
        dns = []
        if runtime:
            # gVisor has its own network stack, so Docker's embedded DNS (127.0.0.11,
            # implemented with iptables inside the container) does not answer. The
            # guard gets plain public resolvers instead; the browser never resolves
            # names itself (everything goes through the guard).
            resolv = self.evidence_dir.parent / ".guard_resolv.conf"
            if not resolv.exists():
                resolv.write_text("".join(f"nameserver {ns}\n" for ns in GUARD_DNS))
                os.chmod(resolv, 0o644)
            dns = ["-v", f"{resolv}:/etc/resolv.conf:ro"]
        # create -> attach both networks -> start: gVisor cannot hot-plug a
        # network interface into a running container.
        await _run(
            "docker", "create", "--name", self.proxy, *runtime, *dns,
            "--network", self.net, "--network-alias", "egress",
            "--memory", "256m", "--cpus", "0.5", "--pids-limit", "128",
            "--read-only", "--tmpfs", "/tmp:rw,size=64m,mode=1777",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{guard_dir}:/evidence",
            "-v", f"{PROXY_DIR}:/addon:ro",
            "-e", "CC_PROXY_LOG=/evidence/proxy_log.jsonl",
            "-e", f"CC_BLOCK_HOSTS={SELF_HOSTS}",
            "--user", "mitmproxy", "--entrypoint", "mitmdump",
            PROXY_IMAGE,
            "-q", "-s", "/addon/egress_guard.py",
            "--listen-port", "8080",
            "--set", "confdir=/tmp/mitm",
            "--set", "connection_strategy=lazy",
            "--set", "block_global=false",
        )
        # Give the guard (and only the guard) a route to the internet.
        await _run("docker", "network", "connect", "bridge", self.proxy)
        await _run("docker", "start", self.proxy)
        await self._wait_for_proxy()
        # The browser reaches the guard by IP: name lookups via Docker DNS do not
        # work under gVisor, and an IP leaves nothing for the page to influence.
        _, ip, _ = await _run("docker", "inspect", "-f",
                              "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % self.net, self.proxy)
        proxy_url = f"http://{ip.strip()}:8080" if ip.strip() else "http://egress:8080"

        args = [
            "docker", "run", "-i", "--rm", "--name", self.sbx,
            "--network", self.net,
            "--read-only", "--tmpfs", "/tmp:rw,size=512m,mode=1777",
            "--memory", MEMORY, "--memory-swap", MEMORY, "--cpus", CPUS,
            "--pids-limit", PIDS, "--shm-size", "64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-e", f"CC_PROXY={proxy_url}",
        ]
        if RUNTIME and RUNTIME != "runc":
            args += ["--runtime", RUNTIME]
        args.append(SANDBOX_IMAGE)
        self.proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=64 * 1024 * 1024,
        )
        asyncio.create_task(self._drain_stderr())
        ready = await self._read(timeout=60)
        if not ready.get("ok"):
            raise RuntimeError(f"sandbox failed to start: {ready}")
        return ready

    async def _wait_for_proxy(self):
        for _ in range(40):
            _, state, _ = await _run(
                "docker", "inspect", "-f", "{{.State.Running}}", self.proxy, check=False
            )
            if state.strip() == "true":
                # mitmdump -q is silent; probe the port from inside the container.
                c, _, _ = await _run(
                    "docker", "exec", self.proxy, "python3", "-c",
                    "import socket;socket.create_connection(('127.0.0.1',8080),1)",
                    check=False,
                )
                if c == 0:
                    return
            await asyncio.sleep(0.25)
        raise RuntimeError("egress guard did not start")

    async def _drain_stderr(self):
        try:
            while True:
                chunk = await self.proc.stderr.read(4096)
                if not chunk:
                    break
                self.stderr_tail = (self.stderr_tail + chunk)[-4000:]
        except Exception:
            pass

    async def _read(self, timeout=STEP_TIMEOUT):
        try:
            line = await asyncio.wait_for(self.proc.stdout.readline(), timeout)
        except asyncio.TimeoutError:
            await self.kill()
            raise SandboxDied("timeout", "step exceeded time limit")
        if not line:
            code = await self.proc.wait()
            raise SandboxDied(code, self.stderr_tail.decode(errors="replace")[-600:])
        return json.loads(line)

    async def call(self, cmd: dict, timeout=STEP_TIMEOUT) -> dict:
        if self.proc is None or self.proc.returncode is not None:
            raise SandboxDied(self.proc.returncode if self.proc else None)
        try:
            self.proc.stdin.write((json.dumps(cmd) + "\n").encode())
            await self.proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            code = await self.proc.wait()
            raise SandboxDied(code, self.stderr_tail.decode(errors="replace")[-600:])
        return await self._read(timeout)

    async def kill(self):
        await _run("docker", "rm", "-f", self.sbx, check=False)

    async def destroy(self) -> dict:
        """Tear everything down and verify nothing is left behind."""
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.stdin.write(b'{"cmd":"close"}\n')
                await self.proc.stdin.drain()
                await asyncio.wait_for(self.proc.wait(), 5)
            except Exception:
                pass
        await _run("docker", "rm", "-f", self.sbx, check=False)
        await _run("docker", "rm", "-f", self.proxy, check=False)
        await _run("docker", "network", "rm", self.net, check=False)
        _, left, _ = await _run(
            "docker", "ps", "-a", "--filter", f"name=cc-.*-{self.id}", "--format", "{{.Names}}",
            check=False,
        )
        _, nets, _ = await _run(
            "docker", "network", "ls", "--filter", f"name={self.net}", "--format", "{{.Name}}",
            check=False,
        )
        leftovers = [x for x in (left.split() + nets.split()) if x]
        return {"destroyed": not leftovers, "leftovers": leftovers}
