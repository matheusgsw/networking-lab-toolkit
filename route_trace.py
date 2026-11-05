"""Traceroute nativo com argumentos seguros e resultados estruturados.

O programa do sistema realiza as sondagens. Este módulo nunca usa shell e
confirma a chegada pelo endereço respondente, não pelo código de saída.
"""

import ipaddress
import math
import os
import platform
import re
import shutil
import socket
import subprocess


def _resolve_destination(host):
    if not isinstance(host, str) or not host or host.startswith("-") or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in host
    ):
        raise ValueError("informe um hostname ou IP sem espaços ou opções")
    # IP literal evita resolução desnecessária e preserva a família pedida.
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
        for family, _, _, _, address in answers:
            if family in (socket.AF_INET, socket.AF_INET6):
                return str(ipaddress.ip_address(address[0]))
        raise OSError("o resolvedor não retornou endereços IPv4 ou IPv6")


def _same_address(left, right):
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except (ValueError, TypeError):
        return False


def _ip_in_tokens(tokens):
    for token in tokens:
        token = token.strip("()[]")
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return None


def parse_hops(output, method):
    """Extrai saltos numéricos de traceroute/tracert, inclusive respostas parciais."""
    hops = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not match:
            continue
        ttl, body = int(match.group(1)), match.group(2)
        address = _ip_in_tokens(body.split())
        # Um salto tem IP, asterisco de timeout ou um tempo; evita cabeçalhos.
        timings = re.findall(r"(<\s*)?(\d+(?:[.,]\d+)?)\s*ms\b", body)
        if address is None and "*" not in body and not timings:
            continue
        probes = [float(value.replace(",", ".")) for _, value in timings]
        hop = {
            "ttl": ttl,
            "address": address,
            "rtt_ms": probes[0] if probes else None,
            "timeout": address is None,
        }
        if any(less_than for less_than, _ in timings):
            # tracert imprime <1 ms; não tratamos o limite como medição exata.
            hop["rtt_is_upper_bound"] = bool(timings[0][0])
        if method == "tracert":
            hop["probe_rtt_ms"] = probes
        marker = re.search(r"!\S+", body)
        if marker:
            hop["annotation"] = marker.group(0)
        hops.append(hop)
    return hops


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def trace_route(host, max_hops=12, timeout=1.0):
    """Executa traceroute com até 64 saltos e prazo total máximo de 300s.

    DNS obedece ao resolvedor do SO; o timeout é por sondagem e não limita DNS.
    Rotas incompletas são resultados válidos com completed=False. Falhas de
    instalação ou execução levantam RuntimeError/OSError em vez de fingir rota.
    """
    if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 1 <= max_hops <= 64:
        raise ValueError("max_hops deve ser inteiro entre 1 e 64")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("timeout deve ser maior que zero e no máximo 60 segundos")

    destination = _resolve_destination(host)
    version = ipaddress.ip_address(destination).version
    system = platform.system()
    method = "tracert" if system == "Windows" else "traceroute"
    name = "traceroute6" if system == "Darwin" and version == 6 else method
    executable = shutil.which(name)
    if not executable:
        if system == "Windows":
            hint = "verifique se tracert.exe está disponível no PATH do Windows"
        elif system == "Darwin":
            hint = f"verifique o utilitário {name} do macOS no PATH"
        else:
            hint = "instale o pacote traceroute (Debian/Ubuntu: sudo apt install traceroute)"
        raise RuntimeError(f"ferramenta {name} não encontrada; {hint}")

    if system == "Windows":
        command = [executable, "-d", f"-{version}", "-h", str(max_hops),
                   "-w", str(max(1, math.ceil(timeout * 1000))), destination]
        probes = 3
    else:
        command = [executable]
        if version == 6 and system != "Darwin":
            command.append("-6")
        command.extend(["-n", "-q", "1", "-m", str(max_hops), "-w", str(timeout), destination])
        probes = 1

    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    timed_out = False
    try:
        process = subprocess.run(command, capture_output=True, text=True,
                                 errors="replace", check=False, env=environment,
                                 timeout=min(300, max_hops * timeout * probes + 5))
        stdout, stderr = process.stdout, process.stderr
        if process.returncode != 0:
            detail = (stderr or stdout).strip()[-1000:]
            raise RuntimeError(f"{name} falhou (código {process.returncode}): {detail or 'sem detalhes'}")
    except subprocess.TimeoutExpired as error:
        stdout, stderr = _text(error.stdout), _text(error.stderr)
        timed_out = True

    hops = parse_hops(stdout, method)
    if not hops and not timed_out:
        detail = (stderr or stdout).strip()[-1000:]
        raise RuntimeError(f"{name} não retornou saltos reconhecíveis: {detail or 'saída vazia'}")
    completed = not timed_out and any(
        _same_address(hop["address"], destination) and not hop.get("annotation")
        for hop in hops
    )
    return {
        "host": host,
        "destination": destination,
        "method": method,
        "completed": completed,
        "timed_out": timed_out,
        "max_hops": max_hops,
        "timeout_seconds": timeout,
        "hops": hops,
        "raw_output": stdout,
        "warnings": stderr.strip(),
    }
