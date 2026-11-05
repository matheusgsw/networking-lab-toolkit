# Networking Lab Toolkit

Uma CLI de diagnóstico de rede para consultar DNS, verificar conectividade TCP/HTTP, analisar endereços IP e acompanhar rotas com traceroute.

**Python 3.10+ · Sem dependências Python externas · IPv4 e IPv6 · Saída JSON · Licença MIT**

Criado para estudar redes e automatizar diagnósticos pequenos. Use os testes ativos em sistemas próprios ou com autorização.

## Início rápido

Baixe o projeto ou clone o repositório depois de publicado:

```bash
git clone https://github.com/matheusgsw/networking-lab-toolkit.git
cd networking-lab-toolkit
python3 toolkit.py --help
python3 toolkit.py dns localhost
python3 toolkit.py ip 192.168.1.10
python3 toolkit.py subnet 192.168.10.42/24
```

Não é necessário executar `pip install`. No Windows, use `py -3` no lugar de `python3`, se necessário. Para consultar a versão, execute `python3 toolkit.py --version`.

### Dependência do traceroute

Os demais comandos usam apenas a biblioteca padrão do Python. O traceroute utiliza uma ferramenta nativa disponível no `PATH`:

| Sistema | Preparação |
| --- | --- |
| Debian / Ubuntu | `sudo apt-get update && sudo apt-get install traceroute` |
| Fedora | `sudo dnf install traceroute` |
| macOS | Normalmente já possui `/usr/sbin/traceroute` e `traceroute6` |
| Windows | Usa `tracert.exe`, incluído no sistema |

A CLI explica o que falta se não encontrar a ferramenta. Ela não instala pacotes nem solicita privilégios automaticamente.

## Comandos

| Comando | Função | Exemplo |
| --- | --- | --- |
| `dns` | Resolver um nome em endereços únicos IPv4/IPv6 | `python3 toolkit.py dns localhost` |
| `tcp` | Testar uma conexão com uma porta TCP | `python3 toolkit.py tcp 127.0.0.1 8000 --timeout 2` |
| `http` | Verificar a resposta HTTP(S) de uma URL | `python3 toolkit.py http http://127.0.0.1:8000/` |
| `ip` | Analisar formato, versão e classificação de um IP | `python3 toolkit.py ip 2001:db8::1` |
| `subnet` | Calcular rede, máscara e total de endereços | `python3 toolkit.py subnet 192.168.10.42/24` |
| `traceroute` | Mostrar os saltos e verificar se o destino respondeu | `python3 toolkit.py traceroute 127.0.0.1 --max-hops 3` |

Cada comando aceita `--help`, `--json` e `--output ARQUIVO`:

```bash
python3 toolkit.py tcp --help
python3 toolkit.py ip 192.168.1.10 --json
python3 toolkit.py subnet 192.168.10.0/24 --json --output report-subnet.json
```

### DNS

Usa o resolvedor do sistema operacional, que também pode consultar o arquivo de hosts e caches locais. Não faz enumeração de subdomínios nem consulta um servidor DNS escolhido pelo usuário. A lista retornada depende da máquina. `localhost` pode ter IPv4, IPv6 ou ambos.

### Conectividade TCP e HTTP

O teste `tcp` abre e fecha uma conexão com **uma única porta**, sem enviar dados de aplicação. Ele não faz varredura de portas. A conexão aceita não demonstra que HTTP ou outro protocolo funciona. `duration_ms` inclui resolução e conexão; não é o RTT de um ping.

O teste `http` envia um GET, acompanha redirecionamentos HTTP(S) e verifica o status sem baixar o corpo. Respostas finais 2xx são sucesso; respostas HTTP 4xx/5xx retornam falha, mesmo que o servidor esteja acessível. O resultado informa a URL final e o status. URLs com credenciais são rejeitadas. A verificação TLS e os proxies configurados no ambiente são preservados.

`--timeout` aceita valores maiores que zero e de até 60 segundos. O padrão é 2 segundos para TCP e 5 para HTTP. O limite é por tentativa/operação de socket; vários endereços ou redirecionamentos podem aumentar o tempo total. **A resolução DNS é controlada pelo SO e não é limitada por essa opção.**

### Análise de IP e sub-redes

Os comandos `ip` e `subnet` são locais: não enviam pacotes. A análise informa versão, forma expandida, ponteiro DNS reverso e flags como loopback, link-local e multicast. O ponteiro reverso é calculado, não consultado. IPv6 com escopo, por exemplo `fe80::1%eth0`, expõe também `scope_id`.

As classificações seguem `ipaddress` da versão de Python instalada. `is_private` também inclui faixas de uso especial; não se limita às redes privadas RFC 1918. Não indica localização, proprietário ou reputação do IP.

A sub-rede é normalizada: `192.168.10.42/24` produz `192.168.10.0/24`. `total_addresses` conta todos os endereços, não apenas hosts utilizáveis. IPv6 não tem broadcast. O cálculo não enumera os endereços, mesmo em redes grandes.

### Traceroute

```bash
python3 toolkit.py traceroute 127.0.0.1 --max-hops 3 --timeout 1
python3 toolkit.py traceroute ::1 --max-hops 3 --json
```

A tabela mostra número do salto, endereço e RTT. `*` indica ausência de resposta reconhecida. O JSON inclui os saltos, a saída original e os indicadores `completed` e `timed_out`.

- O destino só é marcado como alcançado quando seu endereço aparece em uma resposta sem anotação de erro. Código de saída zero do utilitário nativo não basta.
- Rotas incompletas preservam os saltos coletados, retornam `ok: false` e código de saída `1`.
- O limite padrão é 12 saltos; `--max-hops` aceita de 1 a 64. A espera padrão é de 1 segundo por sonda. O processo tem um limite total de até 300 segundos, além do tempo de resolução DNS.
- Linux/macOS usam uma sonda UDP por salto; Windows usa as três sondas ICMP do `tracert`. No Windows, `<1 ms` é preservado como limite superior, não como medida exata.
- Para nomes com vários IPs, usa o primeiro endereço IPv4/IPv6 fornecido pelo resolvedor. Informe um IP literal para escolher o destino.

Firewalls, VPNs e ambientes de nuvem podem bloquear essas sondas. Traceroute usa a rede nativa, não o proxy HTTP; asteriscos ou uma rota incompleta não provam que um equipamento está desligado. O programa não contorna restrições da rede.

## Exportação JSON

```bash
python3 toolkit.py subnet 192.168.10.0/24 --output report-subnet.json
```

O terminal continua legível; o arquivo contém JSON UTF-8. Com `--json`, o terminal também recebe JSON:

```json
{
  "ok": true,
  "command": "subnet",
  "data": {
    "network": "192.168.10.0/24",
    "version": 4,
    "prefix_length": 24,
    "netmask": "255.255.255.0",
    "total_addresses": 256,
    "broadcast": "192.168.10.255"
  }
}
```

Falhas de operação usam `ok: false`, `command` e `error`. Rotas incompletas incluem também `data` com os resultados parciais. Falhas também podem ser exportadas, o que ajuda a comparar diagnósticos.

Arquivos existentes **não são sobrescritos**. Escolha outro nome ou remova conscientemente o relatório anterior. A pasta de destino precisa existir. Se a exportação falhar, o resultado continua disponível no terminal com código de saída `1`. Relatórios podem conter endereços e detalhes da sua rede; revise-os antes de compartilhar.

| Código | Significado |
| --- | --- |
| `0` | Diagnóstico concluído com sucesso |
| `1` | Falha de diagnóstico, rota incompleta ou erro de exportação |
| `2` | Argumentos inválidos ou ausentes |
| `130` | Operação interrompida com `Ctrl+C` |

Erros de argumentos seguem a saída de ajuda do `argparse`, mesmo com `--json`. Uma interrupção também é informada em texto.

## Laboratório local, passo a passo

Em um terminal, dentro do projeto:

```bash
python3 -m http.server 8000 --bind 127.0.0.1 --directory lab
```

O servidor fica acessível apenas na própria máquina. Em outro terminal:

```bash
python3 toolkit.py dns localhost
python3 toolkit.py tcp 127.0.0.1 8000
python3 toolkit.py http http://127.0.0.1:8000/
python3 toolkit.py ip 127.0.0.1
python3 toolkit.py subnet 127.0.0.1/8
python3 toolkit.py traceroute 127.0.0.1 --max-hops 3
python3 toolkit.py http http://127.0.0.1:8000/ --json --output report-http.json
```

Compare TCP e HTTP: um verifica conexão, o outro verifica a resposta do protocolo. Encerre o servidor com `Ctrl+C` no primeiro terminal e repita os dois testes; ambos deverão falhar se nenhum outro serviço estiver usando a porta.

## Testes e CI

```bash
python3 -m unittest discover -s tests -v
```

Os testes não dependem de Internet. Incluem sockets TCP e servidor HTTP reais em loopback, DNS simulado, IPv4/IPv6, argumentos inválidos, exportação sem sobrescrita e análise de saídas de traceroute Linux, macOS e Windows. Um ambiente que proíba sockets locais precisa permitir loopback para executar toda a suíte.

O GitHub Actions está configurado para Python 3.10, 3.12 e 3.14 no Linux, com a suíte completa e smoke tests de traceroute em loopback. Testes de formatos de outros sistemas usam simulação; não substituem uma execução nativa nesses sistemas.

## Organização do projeto

```text
networking-lab-toolkit/
├── toolkit.py              # CLI, DNS, TCP, HTTP, IP, sub-redes e exportação
├── route_trace.py          # Execução e análise do traceroute nativo
├── lab/index.html          # Página do laboratório HTTP local
├── tests/                  # Testes automatizados sem Internet
├── .github/workflows/      # Validação no GitHub Actions
└── LICENSE
```

Para estudar o código, comece por `build_parser()`, siga para `main()` e depois acompanhe uma função de diagnóstico. Próximos exercícios: criar um comparador de relatórios e acrescentar testes para cada comportamento novo.

## Licença

[MIT](LICENSE).
