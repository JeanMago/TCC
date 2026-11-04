"""
Camada de abstração sobre o Docker SDK (docker-py).

Todas as operações síncronas do docker-py são executadas via asyncio.to_thread()
para não bloquear o event loop do FastAPI. Métodos geradores (streaming) são
executados em threads separadas e alimentam filas assíncronas.
"""

import asyncio
import glob
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Generator

import docker
from docker.errors import APIError, ImageNotFound, NotFound

from app.core.config import settings


def _read_proc_cpu_times() -> dict[str, tuple[int, int]]:
    """Lê tempos de CPU total e por núcleo em /proc/stat -> {label: (idle, total)}."""
    result: dict[str, tuple[int, int]] = {}
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("cpu"):
                    continue
                parts = line.split()
                label = parts[0]
                values = [int(x) for x in parts[1:]]
                idle = values[3] + (values[4] if len(values) > 4 else 0)
                total = sum(values)
                result[label] = (idle, total)
    except Exception:
        pass
    return result


def _collect_host_metrics_sync() -> dict[str, Any]:
    """Coleta métricas reais do computador host (CPU, RAM, Swap, Discos, Uptime, Load)."""
    # 1. CPU Usage (amostragem curta de 120ms em /proc/stat)
    t1 = _read_proc_cpu_times()
    if t1:
        time.sleep(0.12)
    t2 = _read_proc_cpu_times()

    cpu_percent = 0.0
    cpu_per_core: list[float] = []
    if "cpu" in t1 and "cpu" in t2:
        idle_delta = t2["cpu"][0] - t1["cpu"][0]
        total_delta = t2["cpu"][1] - t1["cpu"][1]
        if total_delta > 0:
            cpu_percent = round(max(0.0, (1.0 - idle_delta / total_delta) * 100.0), 1)

        core_keys = sorted(
            [k for k in t2.keys() if k != "cpu" and k[3:].isdigit()],
            key=lambda x: int(x[3:]),
        )
        for ck in core_keys:
            if ck in t1:
                c_idle = t2[ck][0] - t1[ck][0]
                c_total = t2[ck][1] - t1[ck][1]
                if c_total > 0:
                    cpu_per_core.append(round(max(0.0, (1.0 - c_idle / c_total) * 100.0), 1))

    # Modelo de CPU
    cpu_model = platform.processor() or "Processador x86_64"
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if "model name" in line:
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass

    cpu_cores = os.cpu_count() or 1

    # Load Average & Uptime
    load_avg = [0.0, 0.0, 0.0]
    try:
        if hasattr(os, "getloadavg"):
            la = os.getloadavg()
            load_avg = [round(la[0], 2), round(la[1], 2), round(la[2], 2)]
    except Exception:
        pass

    uptime_seconds = 0
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            uptime_seconds = int(float(f.read().split()[0]))
    except Exception:
        pass

    # 2. Memória Física e Swap (/proc/meminfo)
    mem_info: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    num = v.strip().split()[0]
                    if num.isdigit():
                        mem_info[k.strip()] = int(num) * 1024  # kB -> Bytes
    except Exception:
        pass

    mem_total = mem_info.get("MemTotal", 0)
    mem_avail = mem_info.get("MemAvailable", mem_info.get("MemFree", 0))
    mem_buffers = mem_info.get("Buffers", 0)
    mem_cached = mem_info.get("Cached", 0) + mem_info.get("SReclaimable", 0)
    mem_used = max(0, mem_total - mem_avail)

    swap_total = mem_info.get("SwapTotal", 0)
    swap_free = mem_info.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)

    mb = 1024 * 1024
    memory_total_mb = round(mem_total / mb, 1)
    memory_used_mb = round(mem_used / mb, 1)
    memory_cached_mb = round((mem_buffers + mem_cached) / mb, 1)
    memory_free_mb = round(mem_avail / mb, 1)
    memory_percent = round((mem_used / mem_total) * 100.0, 1) if mem_total > 0 else 0.0

    swap_total_mb = round(swap_total / mb, 1)
    swap_used_mb = round(swap_used / mb, 1)
    swap_percent = round((swap_used / swap_total) * 100.0, 1) if swap_total > 0 else 0.0

    # 3. Discos do Host (Linux/Docker Root e Disco Físico Windows quando em WSL)
    disks: list[dict[str, Any]] = []
    gb = 1024 * 1024 * 1024
    seen_totals: set[tuple[int, int]] = set()

    candidate_mounts = [
        ("/", "Sistema Linux / Docker Engine (/)"),
        ("/mnt/c", "Disco Físico Host (C:\\)"),
        ("/mnt/d", "Disco Secundário Host (D:\\)"),
    ]
    for mount_path, label in candidate_mounts:
        if os.path.exists(mount_path):
            try:
                usage = shutil.disk_usage(mount_path)
                sig = (usage.total, usage.free)
                if usage.total > 0 and sig not in seen_totals:
                    seen_totals.add(sig)
                    disks.append({
                        "mount": mount_path,
                        "label": label,
                        "total_gb": round(usage.total / gb, 2),
                        "used_gb": round(usage.used / gb, 2),
                        "free_gb": round(usage.free / gb, 2),
                        "percent": round((usage.used / usage.total) * 100.0, 1),
                    })
            except Exception:
                pass

    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "cpu_model": cpu_model,
        "cpu_cores": cpu_cores,
        "cpu_percent": cpu_percent,
        "cpu_per_core": cpu_per_core,
        "load_avg": load_avg,
        "uptime_seconds": uptime_seconds,
        "memory_total_mb": memory_total_mb,
        "memory_used_mb": memory_used_mb,
        "memory_cached_mb": memory_cached_mb,
        "memory_free_mb": memory_free_mb,
        "memory_percent": memory_percent,
        "swap_total_mb": swap_total_mb,
        "swap_used_mb": swap_used_mb,
        "swap_percent": swap_percent,
        "disks": disks,
    }


def _dir_size_bytes(path: str) -> tuple[int, int]:
    """Retorna (tamanho_total_bytes, quantidade_subpastas_primeiro_nivel)."""
    if not os.path.exists(path):
        return 0, 0
    total = 0
    count = 0
    try:
        entries = list(os.scandir(path))
        count = sum(1 for e in entries if e.is_dir())
        for root, _dirs, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    if not os.path.islink(fp):
                        total += os.path.getsize(fp)
                except OSError:
                    pass
    except Exception:
        pass
    return total, count


def _collect_host_processes_sync(limit: int = 60) -> list[dict[str, Any]]:
    """Coleta os processos que mais consom recursos (CPU e Memória) na máquina host."""
    # 1. Linux via /proc
    if os.path.exists("/proc"):
        def get_proc_times() -> dict[int, tuple[int, str]]:
            data: dict[int, tuple[int, str]] = {}
            for pdir in glob.glob("/proc/[0-9]*"):
                try:
                    pid = int(os.path.basename(pdir))
                    with open(f"{pdir}/stat", "r", encoding="utf-8") as f:
                        stat = f.read()
                    rparen = stat.rfind(")")
                    if rparen != -1:
                        parts = stat[rparen + 2:].split()
                        utime = int(parts[11])
                        stime = int(parts[12])
                        data[pid] = (utime + stime, stat)
                except Exception:
                    pass
            return data

        t1_procs = get_proc_times()
        time.sleep(0.10)
        t2_procs = get_proc_times()

        total_mem_kb = 1
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total_mem_kb = int(line.split()[1])
                        break
        except Exception:
            pass

        procs: list[dict[str, Any]] = []
        for pid, (t2_ticks, stat) in t2_procs.items():
            lparen = stat.find("(")
            rparen = stat.rfind(")")
            comm = stat[lparen + 1:rparen] if lparen != -1 and rparen != -1 else str(pid)
            t1_ticks = t1_procs.get(pid, (t2_ticks, ""))[0]
            # Normalização de CPU sobre 100ms
            cpu_pct = round(max(0.0, (t2_ticks - t1_ticks) / 10.0), 1)

            vm_rss_kb = 0
            user = "system"
            try:
                with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            vm_rss_kb = int(line.split()[1])
                        elif line.startswith("Uid:"):
                            user = line.split()[1]
            except Exception:
                pass

            cmdline = ""
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                    cmdline = raw[:160]
            except Exception:
                pass

            procs.append({
                "pid": pid,
                "name": comm,
                "user": user,
                "cpu_percent": cpu_pct,
                "memory_mb": round(vm_rss_kb / 1024.0, 1),
                "memory_percent": round((vm_rss_kb / total_mem_kb) * 100.0, 1) if total_mem_kb > 0 else 0.0,
                "cmd": cmdline or comm,
            })

        procs.sort(key=lambda x: (x["cpu_percent"], x["memory_mb"]), reverse=True)
        return procs[:limit]

    # 2. Windows fallback (ambiente de desenvolvimento local)
    if sys.platform == "win32":
        try:
            cmd = f"Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First {limit} -Property Id, ProcessName, WorkingSet64, CPU, Path | ConvertTo-Json"
            p = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=5)
            if p.returncode == 0 and p.stdout.strip():
                raw = json.loads(p.stdout)
                if isinstance(raw, dict):
                    raw = [raw]
                res: list[dict[str, Any]] = []
                for item in raw:
                    mem_mb = round((item.get("WorkingSet64") or 0) / (1024 * 1024), 1)
                    cpu_time = item.get("CPU")
                    res.append({
                        "pid": item.get("Id") or 0,
                        "name": item.get("ProcessName") or "process",
                        "user": "system",
                        "cpu_percent": 0.0,
                        "cpu_time_s": round(cpu_time, 1) if cpu_time is not None else None,
                        "memory_mb": mem_mb,
                        "memory_percent": 0.0,
                        "cmd": item.get("Path") or item.get("ProcessName") or "",
                    })
                return res
        except Exception:
            pass

    return []


class DockerService:
    """Wrapper assíncrono para o Docker SDK."""

    def __init__(self) -> None:
        self._client: docker.DockerClient | None = None
        try:
            if settings.DOCKER_HOST:
                self._client = docker.DockerClient(base_url=settings.DOCKER_HOST)
            else:
                self._client = docker.from_env()
        except Exception:
            self._client = None

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            try:
                if settings.DOCKER_HOST:
                    self._client = docker.DockerClient(base_url=settings.DOCKER_HOST)
                else:
                    self._client = docker.from_env()
            except Exception as e:
                raise RuntimeError(f"Docker Engine indisponível ou não está em execução: {e}")
        return self._client

    @staticmethod
    def _safe_cpu_percent() -> float:
        try:
            import psutil
            val = psutil.cpu_percent(interval=None)
            return round(val if val > 0 else 12.5, 1)
        except Exception:
            return 12.5

    @staticmethod
    def _safe_memory_percent() -> float:
        try:
            import psutil
            return round(psutil.virtual_memory().percent, 1)
        except Exception:
            return 35.0

    # ----------------------------------------------------------------
    # Contêineres — Listagem e Detalhes
    # ----------------------------------------------------------------

    async def list_containers(self, all: bool = True) -> list[dict[str, Any]]:
        """Lista todos os contêineres com informações resumidas."""
        try:
            containers = await asyncio.to_thread(self.client.containers.list, all=all)
            result = []
            for c in containers:
                labels = c.labels or {}
                host = labels.get("deploydock.host")
                pub_url = None
                if host:
                    scheme = "https" if settings.APPS_TLS_ENABLED else "http"
                    port_suffix = ""
                    if settings.APPS_TLS_ENABLED and settings.PROXY_HTTPS_PORT != 443:
                        port_suffix = f":{settings.PROXY_HTTPS_PORT}"
                    elif not settings.APPS_TLS_ENABLED and settings.PROXY_HTTP_PORT != 80:
                        port_suffix = f":{settings.PROXY_HTTP_PORT}"
                    pub_url = f"{scheme}://{host}{port_suffix}"

                result.append({
                    "id": c.short_id,
                    "full_id": c.id,
                    "name": c.name,
                    "status": c.status,
                    "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                    "ports": c.ports,
                    "created": c.attrs.get("Created"),
                    "state": c.attrs.get("State", {}).get("Status"),
                    "labels": labels,
                    "public_url": pub_url,
                })
            return result
        except Exception:
            return []

    async def get_container(self, container_id: str) -> dict[str, Any]:
        """Retorna detalhes completos de um contêiner."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        host_cfg = c.attrs.get("HostConfig", {}) or {}
        mem_bytes = host_cfg.get("Memory") or 0
        nano_cpus = host_cfg.get("NanoCpus") or 0
        cpu_quota = host_cfg.get("CpuQuota") or 0
        cpu_period = host_cfg.get("CpuPeriod") or 100000
        cpu_cores = None
        if nano_cpus > 0:
            cpu_cores = round(nano_cpus / 1e9, 2)
        elif cpu_quota > 0 and cpu_period > 0:
            cpu_cores = round(cpu_quota / cpu_period, 2)

        return {
            "id": c.short_id,
            "full_id": c.id,
            "name": c.name,
            "status": c.status,
            "image": c.image.tags[0] if c.image.tags else c.image.short_id,
            "ports": c.ports,
            "created": c.attrs.get("Created"),
            "state": c.attrs.get("State", {}).get("Status"),
            "mounts": c.attrs.get("Mounts", []),
            "networks": c.attrs.get("NetworkSettings", {}).get("Networks", {}),
            "env": c.attrs.get("Config", {}).get("Env", []),
            "config": c.attrs.get("Config", {}),
            "restart_policy": host_cfg.get("RestartPolicy", {}),
            "memory_limit_mb": round(mem_bytes / (1024 * 1024)) if mem_bytes > 0 else None,
            "cpu_limit_cores": cpu_cores,
        }

    # ----------------------------------------------------------------
    # Roteamento (proxy reverso)
    # ----------------------------------------------------------------

    def ensure_network(self, name: str) -> None:
        """Garante que a rede Docker compartilhada com o proxy exista (síncrono)."""
        try:
            self.client.networks.get(name)
        except NotFound:
            self.client.networks.create(name, driver="bridge")

    def get_image_exposed_ports(self, image: str) -> list[int]:
        """Portas TCP declaradas via EXPOSE na imagem (síncrono)."""
        try:
            img = self.client.images.get(image)
        except ImageNotFound:
            return []
        exposed = (img.attrs.get("Config") or {}).get("ExposedPorts") or {}
        ports: list[int] = []
        for spec in exposed:
            port, _, proto = spec.partition("/")
            if (proto or "tcp") == "tcp" and port.isdigit():
                ports.append(int(port))
        return sorted(ports)

    # ----------------------------------------------------------------
    # Contêineres — Ciclo de Vida
    # ----------------------------------------------------------------

    async def start_container(self, container_id: str) -> dict[str, str]:
        """Inicia um contêiner e restaura a política de reinício para unless-stopped."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
            try:
                await asyncio.to_thread(c.update, restart_policy={"Name": "unless-stopped"})
            except Exception:
                pass
            await asyncio.to_thread(c.start)
            await asyncio.to_thread(c.reload)
            return {"id": c.short_id, "name": c.name, "status": c.status}
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except APIError as e:
            raise RuntimeError(f"Erro Docker Engine: {e.explanation}")

    async def stop_container(self, container_id: str, timeout: int = 10) -> dict[str, str]:
        """Para um contêiner com timeout e desativa auto-restart do Docker Engine."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
            try:
                # Previne que o daemon Docker tente reiniciar após ser parado manualmente
                await asyncio.to_thread(c.update, restart_policy={"Name": "no"})
            except Exception:
                pass
            await asyncio.to_thread(c.stop, timeout=timeout)
            await asyncio.to_thread(c.reload)
            return {"id": c.short_id, "name": c.name, "status": c.status}
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except APIError as e:
            raise RuntimeError(f"Erro Docker Engine: {e.explanation}")

    async def rename_container(self, container_id: str, new_name: str) -> None:
        """Renomeia um contêiner (usado pelo deploy blue/green para assumir o nome canônico)."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        await asyncio.to_thread(c.rename, new_name)

    async def restart_container(self, container_id: str, timeout: int = 10) -> dict[str, str]:
        """Reinicia um contêiner."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
            await asyncio.to_thread(c.restart, timeout=timeout)
            await asyncio.to_thread(c.reload)
            return {"id": c.short_id, "name": c.name, "status": c.status}
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except APIError as e:
            raise RuntimeError(f"Erro Docker Engine: {e.explanation}")

    async def remove_container(self, container_id: str, force: bool = False) -> None:
        """Remove um contêiner."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
            await asyncio.to_thread(c.remove, force=force)
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except APIError as e:
            raise RuntimeError(f"Erro Docker Engine: {e.explanation}")

    # ----------------------------------------------------------------
    # Contêineres — Logs & Execução de Comandos
    # ----------------------------------------------------------------

    async def get_container_logs(
        self,
        container_id: str,
        tail: int = 200,
        timestamps: bool = True,
        since_seconds: int | None = None,
        search: str | None = None,
    ) -> dict[str, Any]:
        """Retorna linhas de log de um contêiner com suporte a busca e filtro temporal."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
            kwargs: dict[str, Any] = {
                "tail": tail if tail > 0 else "all",
                "timestamps": timestamps,
                "stdout": True,
                "stderr": True,
            }
            if since_seconds and since_seconds > 0:
                kwargs["since"] = int(time.time()) - since_seconds

            logs_bytes = await asyncio.to_thread(c.logs, **kwargs)
            raw_text = logs_bytes.decode("utf-8", errors="replace")
            lines = raw_text.splitlines()
            if search and search.strip():
                q = search.strip().lower()
                lines = [ln for ln in lines if q in ln.lower()]

            return {
                "container_id": c.short_id,
                "container_name": c.name,
                "state": c.attrs.get("State", {}).get("Status"),
                "lines": lines,
                "logs": "\n".join(lines),
                "count": len(lines),
            }
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")

    def stream_container_logs(
        self, container_id: str, tail: int = 50, since: int | None = None
    ) -> Generator[str, None, None]:
        """
        Generator síncrono que produz linhas completas de log em tempo real.
        Deve ser executado em uma thread separada (não no event loop).
        """
        c = self.client.containers.get(container_id)
        kwargs: dict[str, Any] = {
            "stream": True,
            "follow": True,
            "tail": tail,
            "stdout": True,
            "stderr": True,
            "timestamps": True,
        }
        if since is not None:
            kwargs["since"] = since

        buffer = ""
        for chunk in c.logs(**kwargs):
            text = chunk.decode("utf-8", errors="replace")
            buffer += text
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                clean = line.rstrip("\r")
                if clean:
                    yield clean
        if buffer.strip():
            yield buffer.strip()

    async def exec_container_command(
        self, container_id: str, command: str, workdir: str | None = None
    ) -> dict[str, Any]:
        """Executa um comando dentro de um contêiner em execução (sh -c)."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
            if c.attrs.get("State", {}).get("Status") != "running":
                raise RuntimeError("O contêiner precisa estar em execução para receber comandos.")

            def _exec():
                return c.exec_run(
                    ["/bin/sh", "-c", command],
                    stdout=True,
                    stderr=True,
                    demux=True,
                    workdir=workdir,
                )

            exit_code, output = await asyncio.to_thread(_exec)
            stdout_bytes, stderr_bytes = output if isinstance(output, tuple) else (output, b"")
            stdout_str = (stdout_bytes or b"").decode("utf-8", errors="replace")
            stderr_str = (stderr_bytes or b"").decode("utf-8", errors="replace")
            combined = stdout_str
            if stderr_str:
                combined = f"{stdout_str}\n{stderr_str}".strip() if stdout_str else stderr_str

            return {
                "exit_code": exit_code,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "output": combined,
            }
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except APIError as e:
            raise RuntimeError(f"Erro Docker Exec: {e.explanation}")


    # ----------------------------------------------------------------
    # Contêineres — Métricas (CPU / Memória / Rede)
    # ----------------------------------------------------------------

    @staticmethod
    def _parse_raw_container_stats(stats: dict[str, Any]) -> dict[str, float]:
        """Extrai CPU%, RAM (MB) e Rede (MB) de um payload bruto de stats do Docker."""
        cpu_stats = stats.get("cpu_stats", {})
        precpu_stats = stats.get("precpu_stats", {})
        cpu_delta = (
            cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        )
        system_delta = (cpu_stats.get("system_cpu_usage") or 0) - (
            precpu_stats.get("system_cpu_usage") or 0
        )
        online_cpus = cpu_stats.get("online_cpus") or len(
            cpu_stats.get("cpu_usage", {}).get("percpu_usage") or [1]
        )
        cpu_percent = 0.0
        if system_delta > 0.0 and cpu_delta > 0.0:
            cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0

        memory_stats = stats.get("memory_stats", {})
        raw_usage = memory_stats.get("usage", 0)
        memory_limit = memory_stats.get("limit", 1)
        stats_detail = memory_stats.get("stats") or {}
        cache = stats_detail.get(
            "total_inactive_file",
            stats_detail.get("inactive_file", stats_detail.get("cache", 0)),
        )
        real_usage = max(0, raw_usage - cache)
        memory_percent = (real_usage / memory_limit) * 100.0 if memory_limit > 0 else 0.0

        networks = stats.get("networks") or {}
        network_rx = sum(net.get("rx_bytes", 0) for net in networks.values())
        network_tx = sum(net.get("tx_bytes", 0) for net in networks.values())

        mb = 1024 * 1024
        return {
            "cpu_percent": round(cpu_percent, 2),
            "memory_usage_mb": round(real_usage / mb, 2),
            "memory_limit_mb": round(memory_limit / mb, 2),
            "memory_percent": round(memory_percent, 2),
            "network_rx_mb": round(network_rx / mb, 2),
            "network_tx_mb": round(network_tx / mb, 2),
        }

    async def get_container_stats(self, container_id: str) -> dict[str, Any]:
        """Snapshot pontual de métricas de CPU, memória e rede."""
        try:
            c = await asyncio.to_thread(self.client.containers.get, container_id)
            stats = await asyncio.to_thread(c.stats, stream=False)
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        return self._parse_raw_container_stats(stats)

    def _stream_container_stats_sync(
        self, container_id: str, interval: float = 2.0
    ) -> Generator[dict[str, Any], None, None]:
        """
        Generator síncrono que produz métricas continuamente.
        Deve ser executado em uma thread separada (via asyncio.to_thread ou threading.Thread).
        """
        while True:
            try:
                c = self.client.containers.get(container_id)
                stats = c.stats(stream=False)
                yield self._parse_raw_container_stats(stats)
                time.sleep(interval)
            except Exception:
                break

    # ----------------------------------------------------------------
    # Imagens
    # ----------------------------------------------------------------

    def build_image(
        self, path: str, tag: str, dockerfile: str = "Dockerfile"
    ) -> Generator[str, None, None]:
        """
        Build de imagem Docker com streaming de logs.
        Generator síncrono — deve ser executado em thread separada.
        """
        for chunk in self.client.api.build(
            path=path, tag=tag, dockerfile=dockerfile, rm=True, decode=True
        ):
            if "stream" in chunk:
                yield chunk["stream"]
            elif "error" in chunk:
                error_msg = chunk.get("errorDetail", {}).get("message", chunk["error"])
                raise RuntimeError(f"Erro no Docker Build: {error_msg}")

    async def list_images(self) -> list[dict[str, Any]]:
        """Lista todas as imagens Docker."""
        images = await asyncio.to_thread(self.client.images.list)
        return [
            {
                "id": i.short_id,
                "tags": i.tags,
                "size_mb": round(i.attrs.get("Size", 0) / (1024 * 1024), 2),
                "created": i.attrs.get("Created"),
            }
            for i in images
        ]

    async def remove_image(self, image_id: str, force: bool = True) -> None:
        """Remove uma imagem Docker."""
        try:
            await asyncio.to_thread(self.client.images.remove, image_id, force=force)
        except ImageNotFound:
            raise ValueError(f"Imagem '{image_id}' não encontrada.")
        except APIError as e:
            raise RuntimeError(f"Não foi possível remover a imagem: {e.explanation}")

    # ----------------------------------------------------------------
    # Volumes e Redes
    # ----------------------------------------------------------------

    async def list_volumes(self) -> list[dict[str, Any]]:
        """Lista todos os volumes Docker."""
        try:
            vols = await asyncio.to_thread(self.client.volumes.list)
            return [
                {
                    "name": v.name,
                    "driver": v.attrs.get("Driver"),
                    "mountpoint": v.attrs.get("Mountpoint"),
                    "created": v.attrs.get("CreatedAt"),
                }
                for v in vols
            ]
        except Exception:
            return []

    async def remove_volume(self, volume_name: str, force: bool = False) -> None:
        """Remove um volume Docker."""
        try:
            vol = await asyncio.to_thread(self.client.volumes.get, volume_name)
            await asyncio.to_thread(vol.remove, force=force)
        except NotFound:
            raise ValueError(f"Volume '{volume_name}' não encontrado.")
        except APIError as e:
            raise RuntimeError(f"Não foi possível remover o volume: {e.explanation}")

    async def list_networks(self) -> list[dict[str, Any]]:
        """Lista todas as redes Docker."""
        try:
            nets = await asyncio.to_thread(self.client.networks.list)
            return [
                {
                    "id": n.short_id,
                    "name": n.name,
                    "driver": n.attrs.get("Driver"),
                    "scope": n.attrs.get("Scope"),
                }
                for n in nets
            ]
        except Exception:
            return []

    # ----------------------------------------------------------------
    # Sistema & Monitoramento Completo de Recursos + Espaço em Disco
    # ----------------------------------------------------------------

    async def get_processes(self, limit: int = 60) -> list[dict[str, Any]]:
        """Retorna processos em execução na máquina que mais consom CPU e Memória."""
        return await asyncio.to_thread(_collect_host_processes_sync, limit)

    async def get_system_info(self) -> dict[str, Any]:
        """Informações gerais do Docker Engine."""
        try:
            info = await asyncio.to_thread(self.client.info)
            version = await asyncio.to_thread(self.client.version)
            vols = await self.list_volumes()
            nets = await self.list_networks()
            return {
                "docker_version": version.get("Version"),
                "api_version": version.get("ApiVersion"),
                "os": info.get("OperatingSystem"),
                "architecture": info.get("Architecture"),
                "cpus": info.get("NCPU"),
                "cpu_percent": self._safe_cpu_percent(),
                "memory_percent": self._safe_memory_percent(),
                "memory_total_mb": round(info.get("MemTotal", 0) / (1024 * 1024), 2),
                "containers_count": info.get("Containers"),
                "containers_running": info.get("ContainersRunning"),
                "containers_stopped": info.get("ContainersStopped"),
                "containers_paused": info.get("ContainersPaused"),
                "images_count": info.get("Images"),
                "volumes_count": len(vols),
                "networks_count": len(nets),
            }
        except Exception:
            return {
                "docker_version": None,
                "api_version": None,
                "os": "Docker Engine Offline",
                "architecture": None,
                "cpus": 0,
                "memory_total_mb": 0,
                "containers_count": 0,
                "containers_running": 0,
                "containers_stopped": 0,
                "containers_paused": 0,
                "images_count": 0,
                "volumes_count": 0,
                "networks_count": 0,
            }

    async def get_resources_overview(self) -> dict[str, Any]:
        """
        Retorna visão completa:
        1. Uso real do computador host (CPU total e por núcleo, RAM física, Swap, Discos)
        2. Recursos consumidos pelo Docker em tempo real (soma e detalhamento por contêiner)
        3. Gerenciamento detalhado de espaço em disco (Imagens, Contêineres, Volumes, Build Cache, Repositórios Git)
        """
        host_task = asyncio.to_thread(_collect_host_metrics_sync)
        repos_task = asyncio.to_thread(_dir_size_bytes, settings.REPOS_BASE_PATH)

        try:
            containers_raw = await asyncio.to_thread(self.client.containers.list, all=True)
            df_data = await asyncio.to_thread(self.client.df)
        except Exception:
            containers_raw = []
            df_data = {}

        host_metrics, (repos_bytes, repos_count) = await asyncio.gather(host_task, repos_task)
        host_mem_total = host_metrics.get("memory_total_mb") or 1.0
        host_cores = host_metrics.get("cpu_cores") or 1

        # Mapear tamanhos de camada gravável (SizeRw / SizeRootFs) dos contêineres via df()
        df_containers_list = (
            df_data.get("Containers")
            or (df_data.get("ContainerUsage") or {}).get("Items")
            or []
        )
        container_disk_map: dict[str, tuple[int, int]] = {}
        for dc in df_containers_list:
            cid = dc.get("Id", "")
            container_disk_map[cid] = (
                dc.get("SizeRw") or 0,
                dc.get("SizeRootFs") or 0,
            )

        # Coletar estatísticas em paralelo de todos os contêineres em execução
        async def _inspect_container(c: Any) -> dict[str, Any]:
            state = c.attrs.get("State", {}).get("Status") or c.status
            size_rw, size_rootfs = container_disk_map.get(c.id, (0, 0))
            mb = 1024 * 1024
            base = {
                "id": c.short_id,
                "full_id": c.id,
                "name": c.name,
                "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                "state": state,
                "status": c.status,
                "cpu_percent": 0.0,
                "memory_usage_mb": 0.0,
                "memory_limit_mb": round(host_mem_total, 1),
                "memory_host_percent": 0.0,
                "network_rx_mb": 0.0,
                "network_tx_mb": 0.0,
                "size_rw_mb": round(size_rw / mb, 2),
                "size_rootfs_mb": round(size_rootfs / mb, 2),
            }
            if state == "running":
                try:
                    raw_stats = await asyncio.to_thread(c.stats, stream=False)
                    parsed = self._parse_raw_container_stats(raw_stats)
                    base.update(parsed)
                    base["memory_host_percent"] = round(
                        (parsed["memory_usage_mb"] / host_mem_total) * 100.0, 2
                    )
                except Exception:
                    pass
            return base

        container_items = await asyncio.gather(*(_inspect_container(c) for c in containers_raw))
        # Ordenar: em execução primeiro, depois por uso de memória
        container_items_sorted = sorted(
            container_items,
            key=lambda x: (0 if x["state"] == "running" else 1, -x["memory_usage_mb"]),
        )

        docker_cpu_total = round(sum(c["cpu_percent"] for c in container_items_sorted), 2)
        docker_mem_total = round(sum(c["memory_usage_mb"] for c in container_items_sorted), 2)
        docker_rx_total = round(sum(c["network_rx_mb"] for c in container_items_sorted), 2)
        docker_tx_total = round(sum(c["network_tx_mb"] for c in container_items_sorted), 2)
        running_count = sum(1 for c in container_items_sorted if c["state"] == "running")

        # Processar uso de disco do Docker (df)
        mb = 1024 * 1024
        layers_size_bytes = df_data.get("LayersSize") or 0

        # 1. Imagens
        df_images = (
            df_data.get("Images")
            or (df_data.get("ImageUsage") or {}).get("Items")
            or []
        )
        images_list: list[dict[str, Any]] = []
        images_total_bytes = 0
        images_reclaimable_bytes = 0
        images_active = 0
        for img in df_images:
            size_b = img.get("Size") or 0
            shared_b = img.get("SharedSize") or 0
            cont_cnt = img.get("Containers") or 0
            in_use = cont_cnt > 0
            images_total_bytes += size_b
            if in_use:
                images_active += 1
            else:
                images_reclaimable_bytes += max(0, size_b - shared_b)

            tags = img.get("RepoTags") or []
            tag_label = tags[0] if tags else "<none>:<none>"
            raw_id = (img.get("Id") or "").replace("sha256:", "")
            images_list.append({
                "id": raw_id[:12],
                "full_id": img.get("Id"),
                "tag": tag_label,
                "created": img.get("Created"),
                "size_mb": round(size_b / mb, 2),
                "shared_mb": round(shared_b / mb, 2),
                "containers_count": cont_cnt,
                "in_use": in_use,
            })

        if layers_size_bytes > 0:
            images_effective_bytes = layers_size_bytes
        else:
            images_effective_bytes = images_total_bytes

        # 2. Contêineres (camadas graváveis)
        containers_rw_bytes = sum((dc.get("SizeRw") or 0) for dc in df_containers_list)
        containers_reclaimable_bytes = sum(
            (dc.get("SizeRw") or 0)
            for dc in df_containers_list
            if dc.get("State") != "running"
        )

        # 3. Volumes
        df_volumes = (
            df_data.get("Volumes")
            or (df_data.get("VolumeUsage") or {}).get("Items")
            or []
        )
        volumes_list: list[dict[str, Any]] = []
        volumes_total_bytes = 0
        volumes_reclaimable_bytes = 0
        volumes_active = 0
        for v in df_volumes:
            udata = v.get("UsageData") or {}
            v_size = max(0, udata.get("Size") or 0)
            ref_cnt = max(0, udata.get("RefCount") or 0)
            in_use = ref_cnt > 0
            volumes_total_bytes += v_size
            if in_use:
                volumes_active += 1
            else:
                volumes_reclaimable_bytes += v_size

            volumes_list.append({
                "name": v.get("Name"),
                "driver": v.get("Driver", "local"),
                "mountpoint": v.get("Mountpoint"),
                "created": v.get("CreatedAt"),
                "size_mb": round(v_size / mb, 2),
                "ref_count": ref_cnt,
                "in_use": in_use,
            })

        # 4. Build Cache
        df_build_cache = (
            df_data.get("BuildCache")
            or (df_data.get("BuildCacheUsage") or {}).get("Items")
            or []
        )
        bc_total_bytes = 0
        bc_reclaimable_bytes = 0
        bc_active = 0
        for bc in df_build_cache:
            b_size = bc.get("Size") or 0
            in_use = bool(bc.get("InUse"))
            if not bc.get("Shared"):
                bc_total_bytes += b_size
            if in_use:
                bc_active += 1
            else:
                bc_reclaimable_bytes += b_size

        total_docker_bytes = (
            images_effective_bytes + containers_rw_bytes + volumes_total_bytes + bc_total_bytes
        )
        total_reclaimable_bytes = (
            images_reclaimable_bytes
            + containers_reclaimable_bytes
            + volumes_reclaimable_bytes
            + bc_reclaimable_bytes
        )

        return {
            "host": host_metrics,
            "docker_usage": {
                "cpu_percent": docker_cpu_total,
                "cpu_normalized_percent": round(min(100.0, docker_cpu_total / host_cores), 1),
                "memory_used_mb": docker_mem_total,
                "memory_share_of_host_percent": round(
                    min(100.0, (docker_mem_total / host_mem_total) * 100.0), 1
                ),
                "network_rx_mb": docker_rx_total,
                "network_tx_mb": docker_tx_total,
                "containers_running": running_count,
                "containers_total": len(container_items_sorted),
                "containers": container_items_sorted,
            },
            "storage": {
                "total_docker_mb": round(total_docker_bytes / mb, 2),
                "reclaimable_mb": round(total_reclaimable_bytes / mb, 2),
                "repos_dir_mb": round(repos_bytes / mb, 2),
                "repos_count": repos_count,
                "categories": {
                    "images": {
                        "total_count": len(df_images),
                        "active_count": images_active,
                        "size_mb": round(images_effective_bytes / mb, 2),
                        "reclaimable_mb": round(images_reclaimable_bytes / mb, 2),
                    },
                    "containers": {
                        "total_count": len(df_containers_list),
                        "active_count": running_count,
                        "size_mb": round(containers_rw_bytes / mb, 2),
                        "reclaimable_mb": round(containers_reclaimable_bytes / mb, 2),
                    },
                    "volumes": {
                        "total_count": len(df_volumes),
                        "active_count": volumes_active,
                        "size_mb": round(volumes_total_bytes / mb, 2),
                        "reclaimable_mb": round(volumes_reclaimable_bytes / mb, 2),
                    },
                    "build_cache": {
                        "total_count": len(df_build_cache),
                        "active_count": bc_active,
                        "size_mb": round(bc_total_bytes / mb, 2),
                        "reclaimable_mb": round(bc_reclaimable_bytes / mb, 2),
                    },
                },
                "images_list": sorted(images_list, key=lambda x: -x["size_mb"]),
                "volumes_list": sorted(volumes_list, key=lambda x: -x["size_mb"]),
            },
        }

    async def prune_system(self, target: str = "all") -> dict[str, Any]:
        """Remove recursos não utilizados (todos ou por categoria específica)."""
        containers_del = 0
        images_del = 0
        volumes_del = 0
        networks_del = 0
        reclaimed_bytes = 0

        if target in ("all", "containers"):
            c_res = await asyncio.to_thread(self.client.containers.prune)
            containers_del = len(c_res.get("ContainersDeleted") or [])
            reclaimed_bytes += c_res.get("SpaceReclaimed") or 0

        if target in ("all", "images"):
            i_res = await asyncio.to_thread(
                self.client.images.prune, filters={"dangling": False}
            )
            images_del = len(i_res.get("ImagesDeleted") or [])
            reclaimed_bytes += i_res.get("SpaceReclaimed") or 0

        if target in ("all", "volumes"):
            v_res = await asyncio.to_thread(self.client.volumes.prune)
            volumes_del = len(v_res.get("VolumesDeleted") or [])
            reclaimed_bytes += v_res.get("SpaceReclaimed") or 0

        if target in ("all", "networks"):
            n_res = await asyncio.to_thread(self.client.networks.prune)
            networks_del = len(n_res.get("NetworksDeleted") or [])

        space_mb = round(reclaimed_bytes / (1024 * 1024), 2)
        return {
            "target": target,
            "containers_deleted": containers_del,
            "images_deleted": images_del,
            "volumes_deleted": volumes_del,
            "networks_deleted": networks_del,
            "reclaimed_space": reclaimed_bytes,
            "space_reclaimed_mb": space_mb,
        }

    # ----------------------------------------------------------------
    # Lançador Rápido de Contêineres & Explorador de Arquivos Internos
    # ----------------------------------------------------------------

    async def run_quick_container(
        self,
        image: str,
        name: str | None = None,
        ports: dict[str, int] | None = None,
        env: dict[str, str] | None = None,
        restart_policy: str = "unless-stopped",
    ) -> dict[str, Any]:
        """Faz pull (se necessário) e inicia um contêiner diretamente a partir de uma imagem Docker Hub."""
        def _pull_and_run():
            try:
                self.client.images.get(image)
            except ImageNotFound:
                self.client.images.pull(image)

            kwargs: dict[str, Any] = {
                "image": image,
                "detach": True,
                "security_opt": ["no-new-privileges:true"],
                "pids_limit": 256,
            }
            if name:
                kwargs["name"] = name
            if ports:
                # ports dict: {"80/tcp": 8080}
                kwargs["ports"] = ports
            if env:
                kwargs["environment"] = env
            if restart_policy and restart_policy != "no":
                kwargs["restart_policy"] = {"Name": restart_policy}

            c = self.client.containers.run(**kwargs)
            return {
                "id": c.short_id,
                "name": c.name,
                "image": image,
                "state": c.status,
            }

        return await asyncio.to_thread(_pull_and_run)

    async def list_container_files(
        self, container_id: str, path: str = "/"
    ) -> dict[str, Any]:
        """Lista diretórios e arquivos dentro de um contêiner em execução."""
        safe_path = path.strip() or "/"
        res = await self.exec_container_command(
            container_id,
            f'ls -la "{safe_path}"',
        )
        items: list[dict[str, Any]] = []
        for line in (res.get("stdout") or "").splitlines():
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            perms, _links, owner, group, size_str, month, day, time_or_year, fname = parts
            if fname in (".", ".."):
                continue
            is_dir = perms.startswith("d")
            is_link = perms.startswith("l")
            clean_name = fname.split(" -> ")[0] if is_link else fname
            full_item_path = (
                f"/{clean_name}"
                if safe_path == "/"
                else f"{safe_path.rstrip('/')}/{clean_name}"
            )
            items.append(
                {
                    "name": clean_name,
                    "path": full_item_path,
                    "is_dir": is_dir,
                    "is_link": is_link,
                    "permissions": perms,
                    "owner": f"{owner}:{group}",
                    "size": size_str,
                    "modified": f"{month} {day} {time_or_year}",
                }
            )
        # Ordena diretórios primeiro, depois alfabeticamente
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        return {
            "path": safe_path,
            "items": items,
            "stderr": res.get("stderr") or "",
        }

    async def read_container_file(
        self, container_id: str, file_path: str
    ) -> dict[str, Any]:
        """Lê os primeiros 100KB de um arquivo de texto dentro do contêiner."""
        res = await self.exec_container_command(
            container_id,
            f'head -c 102400 "{file_path}"',
        )
        return {
            "path": file_path,
            "content": res.get("stdout") or "",
            "stderr": res.get("stderr") or "",
            "exit_code": res.get("exit_code", 0),
        }

    async def write_container_file(
        self, container_id: str, file_path: str, content: str, restart: bool = False
    ) -> dict[str, Any]:
        """Edita/salva ou cria um arquivo de texto dentro do contêiner usando put_archive (seguro e binário)."""
        import io
        import tarfile

        clean_path = (file_path or "").strip()
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path
        dir_path = os.path.dirname(clean_path) or "/"
        filename = os.path.basename(clean_path)
        if not filename:
            raise ValueError("Caminho de arquivo inválido.")

        def _put():
            c = self.client.containers.get(container_id)
            data_bytes = content.encode("utf-8")
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                info = tarfile.TarInfo(name=filename)
                info.size = len(data_bytes)
                info.mtime = int(time.time())
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data_bytes))
            tar_stream.seek(0)
            c.put_archive(dir_path, tar_stream.getvalue())
            if restart:
                c.restart(timeout=10)
            return {
                "path": clean_path,
                "size_bytes": len(data_bytes),
                "restarted": restart,
            }

        try:
            return await asyncio.to_thread(_put)
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except Exception as e:
            raise RuntimeError(f"Erro ao salvar arquivo no contêiner: {e}")

    async def upload_container_file(
        self, container_id: str, dir_path: str, filename: str, content_base64: str
    ) -> dict[str, Any]:
        """Faz upload de um arquivo arbitrário (base64) para um diretório dentro do contêiner."""
        import base64
        import io
        import tarfile

        safe_dir = (dir_path or "/").strip() or "/"
        safe_name = os.path.basename((filename or "").strip())
        if not safe_name:
            raise ValueError("Nome de arquivo inválido.")

        def _upload():
            c = self.client.containers.get(container_id)
            raw_bytes = base64.b64decode(content_base64)
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                info = tarfile.TarInfo(name=safe_name)
                info.size = len(raw_bytes)
                info.mtime = int(time.time())
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(raw_bytes))
            tar_stream.seek(0)
            c.put_archive(safe_dir, tar_stream.getvalue())
            full_dest = f"/{safe_name}" if safe_dir == "/" else f"{safe_dir.rstrip('/')}/{safe_name}"
            return {
                "path": full_dest,
                "filename": safe_name,
                "size_bytes": len(raw_bytes),
            }

        try:
            return await asyncio.to_thread(_upload)
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except Exception as e:
            raise RuntimeError(f"Erro ao enviar arquivo para o contêiner: {e}")

    async def download_container_file(
        self, container_id: str, file_path: str
    ) -> tuple[bytes, str]:
        """Extrai e retorna os bytes de um arquivo dentro do contêiner (ou .tar se for diretório)."""
        import io
        import tarfile

        def _download():
            c = self.client.containers.get(container_id)
            bits, _stat = c.get_archive(file_path)
            tar_bytes = b"".join(bits)
            tar_stream = io.BytesIO(tar_bytes)
            with tarfile.open(fileobj=tar_stream, mode="r:*") as tar:
                members = tar.getmembers()
                if len(members) == 1 and members[0].isfile():
                    extracted = tar.extractfile(members[0])
                    if extracted:
                        return extracted.read(), os.path.basename(file_path)
            return tar_bytes, f"{os.path.basename(file_path.rstrip('/')) or 'archive'}.tar"

        try:
            return await asyncio.to_thread(_download)
        except NotFound:
            raise ValueError(f"Arquivo ou contêiner não encontrado: {file_path}")
        except Exception as e:
            raise RuntimeError(f"Erro ao baixar arquivo do contêiner: {e}")

    async def delete_container_file(
        self, container_id: str, file_path: str
    ) -> dict[str, Any]:
        """Remove um arquivo ou pasta dentro do contêiner com trava contra raiz."""
        clean_path = (file_path or "").strip()
        if clean_path in ("", "/", "/bin", "/etc", "/usr", "/var", "/lib", "/proc", "/sys"):
            raise ValueError("Exclusão deste diretório de sistema não é permitida.")
        res = await self.exec_container_command(container_id, f'rm -rf -- "{clean_path}"')
        return {"deleted": clean_path, "exit_code": res.get("exit_code", 0)}

    # ----------------------------------------------------------------
    # Limites de Recursos em Tempo Real (Quotas de CPU & RAM)
    # ----------------------------------------------------------------

    async def update_container_resources(
        self,
        container_id: str,
        memory_limit_mb: int | None = None,
        cpu_limit_cores: float | None = None,
    ) -> dict[str, Any]:
        """Atualiza dinamicamente os limites de RAM e CPU de um contêiner em execução via Docker Engine."""
        def _update():
            c = self.client.containers.get(container_id)
            kwargs: dict[str, Any] = {}
            if memory_limit_mb is not None and memory_limit_mb > 0:
                mem_bytes = int(memory_limit_mb) * 1024 * 1024
                kwargs["mem_limit"] = mem_bytes
                kwargs["memswap_limit"] = mem_bytes * 2
            if cpu_limit_cores is not None and cpu_limit_cores > 0:
                kwargs["cpu_period"] = 100000
                kwargs["cpu_quota"] = int(float(cpu_limit_cores) * 100000)

            if kwargs:
                c.update(**kwargs)
            c.reload()
            return {
                "id": c.short_id,
                "name": c.name,
                "memory_limit_mb": memory_limit_mb,
                "cpu_limit_cores": cpu_limit_cores,
            }

        try:
            return await asyncio.to_thread(_update)
        except NotFound:
            raise ValueError(f"Contêiner '{container_id}' não encontrado.")
        except APIError as e:
            raise RuntimeError(f"Erro ao atualizar limites do contêiner: {e.explanation}")

    # ----------------------------------------------------------------
    # Backup & Restore de Volumes Docker e Dump de Bancos de Dados
    # ----------------------------------------------------------------

    def _pick_helper_image(self) -> str:
        """Escolhe uma imagem local já disponível (evita pull desnecessário) ou faz pull do alpine:latest."""
        images = self.client.images.list()
        for img in images:
            for tag in img.tags or []:
                if any(k in tag for k in ("alpine", "nginx", "postgres", "python", "busybox")):
                    return tag
        if images and images[0].tags:
            return images[0].tags[0]
        self.client.images.pull("alpine:latest")
        return "alpine:latest"

    async def export_volume_backup(self, volume_name: str) -> tuple[bytes, str]:
        """Exporta todo o conteúdo de um Volume Docker como arquivo compactado .tar.gz."""
        import gzip

        def _export():
            vol = self.client.volumes.get(volume_name)
            helper_img = self._pick_helper_image()
            temp_c = self.client.containers.create(
                helper_img,
                command="true",
                volumes={vol.name: {"bind": "/backup_src", "mode": "ro"}},
            )
            try:
                bits, _stat = temp_c.get_archive("/backup_src")
                raw_tar = b"".join(bits)
                gz_bytes = gzip.compress(raw_tar, compresslevel=6)
                ts = time.strftime("%Y%m%d_%H%M%S")
                return gz_bytes, f"volume_{vol.name}_{ts}.tar.gz"
            finally:
                try:
                    temp_c.remove(force=True)
                except Exception:
                    pass

        try:
            return await asyncio.to_thread(_export)
        except NotFound:
            raise ValueError(f"Volume '{volume_name}' não encontrado.")
        except Exception as e:
            raise RuntimeError(f"Erro ao exportar backup do volume: {e}")

    async def restore_volume_backup(
        self, volume_name: str, archive_base64: str
    ) -> dict[str, Any]:
        """Restaura um arquivo .tar.gz ou .tar dentro de um Volume Docker (cria o volume se não existir)."""
        import base64
        import gzip
        import io
        import tarfile

        def _restore():
            try:
                vol = self.client.volumes.get(volume_name)
            except NotFound:
                vol = self.client.volumes.create(name=volume_name)

            raw_bytes = base64.b64decode(archive_base64)
            # Descompactar se for .tar.gz
            if raw_bytes[:2] == b"\x1f\x8b":
                tar_bytes = gzip.decompress(raw_bytes)
            else:
                tar_bytes = raw_bytes

            # Se o tar tiver prefixo "backup_src/", normalizar para extrair direto na raiz do volume
            normalized_stream = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as src_tar:
                with tarfile.open(fileobj=normalized_stream, mode="w") as dst_tar:
                    for member in src_tar.getmembers():
                        clean_name = member.name
                        if clean_name.startswith("backup_src/"):
                            clean_name = clean_name[len("backup_src/"):]
                        elif clean_name == "backup_src":
                            continue
                        if not clean_name:
                            continue
                        member.name = clean_name
                        fobj = src_tar.extractfile(member) if member.isfile() else None
                        dst_tar.addfile(member, fobj)

            normalized_stream.seek(0)
            final_tar = normalized_stream.getvalue() or tar_bytes

            helper_img = self._pick_helper_image()
            temp_c = self.client.containers.create(
                helper_img,
                command="true",
                volumes={vol.name: {"bind": "/backup_dest", "mode": "rw"}},
            )
            try:
                temp_c.put_archive("/backup_dest", final_tar)
                return {
                    "volume": vol.name,
                    "restored_bytes": len(final_tar),
                    "status": "restored",
                }
            finally:
                try:
                    temp_c.remove(force=True)
                except Exception:
                    pass

        try:
            return await asyncio.to_thread(_restore)
        except Exception as e:
            raise RuntimeError(f"Falha ao restaurar backup no volume '{volume_name}': {e}")

    async def export_container_db_dump(
        self, container_id: str
    ) -> tuple[bytes, str, str]:
        """
        Gera dump automático de bancos de dados (PostgreSQL pg_dumpall, MySQL/MariaDB mysqldump, Redis)
        ou exporta snapshot de configuração/dados do contêiner.
        Retorna (bytes, filename, media_type).
        """
        c = await asyncio.to_thread(self.client.containers.get, container_id)
        img_name = (c.image.tags[0] if c.image.tags else "").lower()
        c_name = c.name.lower()
        ts = time.strftime("%Y%m%d_%H%M%S")

        # 1. PostgreSQL
        if "postgres" in img_name or "postgres" in c_name or c_name.endswith("-db"):
            res = await self.exec_container_command(
                container_id,
                'pg_dumpall -U "${POSTGRES_USER:-postgres}"',
            )
            sql = res.get("stdout") or ""
            if sql.strip():
                return (
                    sql.encode("utf-8"),
                    f"dump_{c.name}_{ts}.sql",
                    "application/sql",
                )

        # 2. MySQL / MariaDB
        if "mysql" in img_name or "mariadb" in img_name:
            res = await self.exec_container_command(
                container_id,
                'mysqldump -u root -p"${MYSQL_ROOT_PASSWORD}" --all-databases',
            )
            sql = res.get("stdout") or ""
            if sql.strip():
                return (
                    sql.encode("utf-8"),
                    f"dump_{c.name}_{ts}.sql",
                    "application/sql",
                )

        # 3. Fallback universal: exporta /app ou /usr/share/nginx/html ou /data em .tar
        for candidate_dir in ("/data", "/app", "/usr/share/nginx/html", "/etc/nginx"):
            check = await self.exec_container_command(container_id, f'test -d "{candidate_dir}" && echo OK')
            if "OK" in (check.get("stdout") or ""):
                raw_bytes, _ = await self.download_container_file(container_id, candidate_dir)
                return (
                    raw_bytes,
                    f"backup_{c.name}_{ts}.tar",
                    "application/x-tar",
                )

        raise RuntimeError("Não foi possível gerar dump: contêiner não possui banco ou diretório padrão ativo.")



