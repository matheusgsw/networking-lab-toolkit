#!/usr/bin/env python3
"""Ferramentas de redes para pequenos laboratórios, usando apenas a biblioteca padrão."""

import argparse
import ipaddress
import json
import math
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from route_trace import trace_route


VERSION = "1.0.0"


def host_argument(value):
    """Evita nomes vazios e caracteres que não fazem parte de um destino."""
    if not value or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                        for character in value):
        raise argparse.ArgumentTypeError("informe um hostname ou IP sem espaços")
    return value


def port_argument(value):
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("a porta deve ser um número inteiro") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("a porta deve estar entre 1 e 65535")
    return port


def timeout_argument(value):
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("o timeout deve ser um número") from None
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise argparse.ArgumentTypeError("o timeout deve ser maior que 0 e no máximo 60 segundos")
    return timeout


def network_argument(value):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError("informe uma rede IPv4 ou IPv6 válida, por exemplo 192.168.1.0/24") from None


def ip_argument(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise argparse.ArgumentTypeError("informe um endereço IPv4 ou IPv6 válido") from None


def hops_argument(value):
    try:
        hops = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("o número de saltos deve ser inteiro") from None
    if not 1 <= hops <= 64:
        raise argparse.ArgumentTypeError("use entre 1 e 64 saltos")
    return hops


def url_argument(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise argparse.ArgumentTypeError("URL ou porta inválida") from None
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                   for character in value)
            or (port is not None and not 1 <= port <= 65535)):
        raise argparse.ArgumentTypeError("use uma URL http:// ou https:// sem credenciais")
    return value


def analyze_ip(address):
    """Descreve um IP localmente; reverse_pointer não faz uma consulta DNS."""
    original = ipaddress.ip_address(address)
    # Escopos IPv6 identificam a interface, mas não fazem parte dos bits do IP.
    scope_id = getattr(original, "scope_id", None)
    ip = ipaddress.ip_address(str(original).split("%", 1)[0])
    result = {
        "address": str(original),
        "version": ip.version,
        "compressed": ip.compressed,
        "expanded": ip.exploded,
        "reverse_pointer": ip.reverse_pointer,
        "is_global": ip.is_global,
        "is_private": ip.is_private,
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
        "is_unspecified": ip.is_unspecified,
    }
    if scope_id is not None:
        result["scope_id"] = scope_id
    return result


class HTTPRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Mantém redirecionamentos restritos a HTTP(S) e sem credenciais na URL."""

    def redirect_request(self, request, response, code, message, headers, newurl):
        try:
            url_argument(newurl)
        except argparse.ArgumentTypeError as error:
            raise OSError(f"redirecionamento inválido: {error}") from error
        return super().redirect_request(request, response, code, message, headers, newurl)


def check_http(url, timeout):
    """Faz um GET sem baixar o corpo; preserva TLS e os proxies do ambiente."""
    started = time.perf_counter()
    request = urllib.request.Request(url, headers={"User-Agent": f"NetworkingLabToolkit/{VERSION}"})
    opener = urllib.request.build_opener(HTTPRedirectHandler())
    with opener.open(request, timeout=timeout) as response:
        return {
            "url": url,
            "final_url": response.geturl(),
            "status": response.status,
            "reason": response.reason,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        }


def export_json(path, result):
    """Exporta UTF-8 sem sobrescrever um relatório ou arquivo existente."""
    contents = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    with Path(path).open("x", encoding="utf-8") as output:
        output.write(contents)


def resolve_dns(host):
    """Consulta o resolvedor do sistema; remove endereços duplicados."""
    results = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC,
                                 type=socket.SOCK_STREAM)
    addresses = {
        ("IPv4" if family == socket.AF_INET else "IPv6", address[0])
        for family, _, _, _, address in results
        if family in (socket.AF_INET, socket.AF_INET6)
    }
    if not addresses:
        raise OSError("o resolvedor não retornou endereços IPv4 ou IPv6")
    return {
        "host": host,
        "addresses": [
            {"family": family, "address": address}
            for family, address in sorted(addresses)
        ],
    }


def check_tcp(host, port, timeout):
    """Abre e fecha uma conexão TCP, sem enviar dados de aplicação."""
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as connection:
        address = connection.getpeername()[0]
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
    return {
        "host": host,
        "port": port,
        "address": address,
        "duration_ms": duration_ms,
        "timeout_seconds": timeout,
    }


def subnet_info(cidr):
    """Calcula metadados sem enumerar os endereços da rede."""
    network = ipaddress.ip_network(cidr, strict=False)
    result = {
        "network": str(network),
        "version": network.version,
        "prefix_length": network.prefixlen,
        "netmask": str(network.netmask),
        "total_addresses": network.num_addresses,
    }
    if network.version == 4:
        result["broadcast"] = str(network.broadcast_address)
    return result


def build_parser():
    parser = argparse.ArgumentParser(
        description="Networking Lab Toolkit — diagnóstico de rede em uma CLI.",
        epilog="Use os testes de conexão em sistemas próprios ou com autorização.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    dns = commands.add_parser("dns", help="resolver um hostname em endereços IP")
    dns.add_argument("host", type=host_argument)

    tcp = commands.add_parser("tcp", help="testar uma conexão com uma porta TCP")
    tcp.add_argument("host", type=host_argument)
    tcp.add_argument("port", type=port_argument)
    tcp.add_argument("--timeout", type=timeout_argument, default=2.0,
                     help="timeout por tentativa de conexão, em segundos (padrão: 2; máximo: 60)")

    http = commands.add_parser("http", help="verificar a resposta de um serviço HTTP(S)")
    http.add_argument("url", type=url_argument)
    http.add_argument("--timeout", type=timeout_argument, default=5.0,
                      help="timeout de socket em segundos (padrão: 5)")

    ip = commands.add_parser("ip", help="analisar e classificar um endereço IPv4 ou IPv6")
    ip.add_argument("address", type=ip_argument)

    subnet = commands.add_parser("subnet", help="calcular informações de uma rede IPv4 ou IPv6")
    subnet.add_argument("cidr", type=network_argument,
                        help="rede ou endereço com prefixo, por exemplo 192.168.1.10/24")

    traceroute = commands.add_parser("traceroute", help="mostrar os saltos de uma rota de rede")
    traceroute.add_argument("host", type=host_argument)
    traceroute.add_argument("--max-hops", type=hops_argument, default=12)
    traceroute.add_argument("--timeout", type=timeout_argument, default=1.0,
                            help="espera por sonda em segundos (padrão: 1)")

    for command in (dns, tcp, http, ip, subnet, traceroute):
        command.add_argument("--json", action="store_true", help="emitir resultado em JSON")
        command.add_argument("--output", metavar="ARQUIVO", help="exportar JSON sem sobrescrever arquivos existentes")
    return parser


def print_result(command, data):
    if command == "dns":
        print(f"Resolução de {data['host']}:")
        for address in data["addresses"]:
            print(f"  {address['family']}: {address['address']}")
    elif command == "tcp":
        print(f"Conexão TCP estabelecida: {data['host']} porta {data['port']}")
        print(f"Endereço conectado: {data['address']}")
        print(f"Duração da resolução e conexão: {data['duration_ms']:.3f} ms")
    elif command == "http":
        print(f"HTTP {data['status']} {data['reason']}")
        print(f"URL final: {data['final_url']}")
        print(f"Duração: {data['duration_ms']:.3f} ms")
    elif command == "ip":
        print(f"Endereço: {data['address']} (IPv{data['version']})")
        print(f"Forma expandida: {data['expanded']}")
        print(f"Ponteiro DNS reverso: {data['reverse_pointer']}")
        labels = {
            "is_global": "Global", "is_private": "Privado / uso especial",
            "is_loopback": "Loopback", "is_link_local": "Link-local",
            "is_multicast": "Multicast", "is_reserved": "Reservado",
            "is_unspecified": "Não especificado",
        }
        for flag, label in labels.items():
            print(f"{label}: {'sim' if data[flag] else 'não'}")
    elif command == "traceroute":
        print(f"Rota para {data['host']} ({data['destination']}):")
        print(f"{'SALTO':<7} {'ENDEREÇO':<40} RTT")
        for hop in data["hops"]:
            address = hop["address"] or "*"
            prefix = "<" if hop.get("rtt_is_upper_bound") else ""
            rtt = f"{prefix}{hop['rtt_ms']:.3f} ms" if hop["rtt_ms"] is not None else "*"
            if hop.get("annotation"):
                rtt += f" {hop['annotation']}"
            print(f"{hop['ttl']:<7} {address:<40} {rtt}")
        if data.get("warnings"):
            print(f"Aviso: {data['warnings']}")
        print("Destino alcançado." if data["completed"] else "Rota incompleta: destino não confirmado.")
    elif command == "subnet":
        print(f"Rede: {data['network']} (IPv{data['version']})")
        print(f"Prefixo: /{data['prefix_length']}")
        print(f"Máscara: {data['netmask']}")
        print(f"Total de endereços: {data['total_addresses']}")
        if "broadcast" in data:
            print(f"Broadcast: {data['broadcast']}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    result = {"ok": True, "command": args.command}
    try:
        if args.command == "dns":
            data = resolve_dns(args.host)
        elif args.command == "tcp":
            data = check_tcp(args.host, args.port, args.timeout)
        elif args.command == "http":
            data = check_http(args.url, args.timeout)
        elif args.command == "ip":
            data = analyze_ip(args.address)
        elif args.command == "traceroute":
            data = trace_route(args.host, args.max_hops, args.timeout)
            if not data["completed"]:
                result.update(ok=False, error="rota incompleta: o destino não foi confirmado")
        elif args.command == "subnet":
            data = subnet_info(args.cidr)
        result["data"] = data
    except (OSError, UnicodeError, RuntimeError, ValueError) as error:
        result.update(ok=False, error=str(error))
    except KeyboardInterrupt:
        print("\nOperação interrompida.", file=sys.stderr)
        return 130

    if args.output:
        try:
            export_json(args.output, result)
        except OSError as error:
            # Mantém o resultado do diagnóstico disponível mesmo quando a exportação falha.
            result.update(ok=False, error=f"não foi possível exportar JSON: {error}")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if "data" in result:
            print_result(args.command, result["data"])
        if "error" in result:
            print(f"Falha ao executar {args.command}: {result['error']}", file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
