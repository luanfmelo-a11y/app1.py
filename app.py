import os
import json
import ipaddress
from functools import wraps

from flask import (
    Flask,
    request,
    jsonify,
    Response,
    render_template_string,
    redirect,
    url_for
)

from werkzeug.middleware.proxy_fix import ProxyFix


# ============================================================
# APP
# ============================================================

app = Flask(__name__)

# IMPORTANTE PARA SERVIDORES ATRÁS DE PROXY
# Ex.: Render, Railway, etc.
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)


# ============================================================
# CONFIGURAÇÃO
# ============================================================

ADMIN_USER = os.environ.get(
    "ADMIN_USER",
    "daviwld"
)

ADMIN_PASS = os.environ.get(
    "ADMIN_PASS",
    "luan4520r"
)

PORT = int(
    os.environ.get(
        "PORT",
        5000
    )
)

MAX_TENTATIVAS = 10

ARQUIVO_APROVADOS = "aprovados.json"
ARQUIVO_PENDENTES = "pendentes.json"
ARQUIVO_BANIDOS = "banidos.json"


# ============================================================
# ARQUIVOS
# ============================================================

def carregar_json(arquivo, padrao):

    try:

        with open(
            arquivo,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except (
        FileNotFoundError,
        json.JSONDecodeError,
        OSError
    ):

        return padrao


def salvar_json(arquivo, dados):

    try:

        arquivo_temp = arquivo + ".tmp"

        with open(
            arquivo_temp,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                dados,
                f,
                ensure_ascii=False,
                indent=2
            )

        os.replace(
            arquivo_temp,
            arquivo
        )

        return True

    except OSError as e:

        print(
            f"[ERRO AO SALVAR] {arquivo}: {e}",
            flush=True
        )

        return False


# ============================================================
# CARREGAMENTO
# ============================================================

IPS_APROVADOS = set(
    carregar_json(
        ARQUIVO_APROVADOS,
        []
    )
)

DISPOSITIVOS_PENDENTES = carregar_json(
    ARQUIVO_PENDENTES,
    {}
)

IPS_BANIDOS = set(
    carregar_json(
        ARQUIVO_BANIDOS,
        []
    )
)

TENTATIVAS_ERRO = {}


# ============================================================
# IP
# ============================================================

def ip_valido(ip):

    try:

        ipaddress.ip_address(ip)

        return True

    except ValueError:

        return False


def obter_ip():

    """
    Depois do ProxyFix, request.remote_addr
    representa o IP encaminhado pelo proxy.

    Em acesso direto, representa o IP da conexão.
    """

    ip = (
        request.remote_addr
        or ""
    ).strip()

    if ip and ip_valido(ip):

        return ip

    return "0.0.0.0"


# ============================================================
# CORS
# ============================================================

@app.after_request
def aplicar_cors(response):

    response.headers[
        "Access-Control-Allow-Origin"
    ] = "*"

    response.headers[
        "Access-Control-Allow-Headers"
    ] = "*"

    response.headers[
        "Access-Control-Allow-Methods"
    ] = "GET, POST, OPTIONS"

    return response


# ============================================================
# BANIMENTO
# ============================================================

@app.before_request
def verificar_banimento():

    if request.method == "OPTIONS":

        return None

    ip = obter_ip()

    if ip in IPS_BANIDOS:

        print(
            f"[BLOQUEADO] {ip}",
            flush=True
        )

        return Response(
            status=404
        )

    return None


# ============================================================
# AUTENTICAÇÃO DO PAINEL
# ============================================================

def requer_admin(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        auth = request.authorization

        ip = obter_ip()

        if (
            auth
            and auth.username == ADMIN_USER
            and auth.password == ADMIN_PASS
        ):

            TENTATIVAS_ERRO.pop(
                ip,
                None
            )

            return func(
                *args,
                **kwargs
            )

        if auth:

            tentativas = (
                TENTATIVAS_ERRO.get(
                    ip,
                    0
                ) + 1
            )

            TENTATIVAS_ERRO[ip] = tentativas

            if tentativas >= MAX_TENTATIVAS:

                IPS_BANIDOS.add(ip)

                salvar_json(
                    ARQUIVO_BANIDOS,
                    sorted(IPS_BANIDOS)
                )

                return Response(
                    status=404
                )

        return Response(
            "Authentication required",
            401,
            {
                "WWW-Authenticate":
                'Basic realm="Painel Admin"'
            }
        )

    return wrapper


# ============================================================
# REGISTRAR ACESSO
# ============================================================

def registrar_pendente(ip):

    user_agent = request.headers.get(
        "User-Agent",
        "desconhecido"
    )

    # Guarda informações adicionais úteis
    dados = {
        "ip": ip,
        "user_agent": user_agent,
        "metodo": request.method,
        "rota": request.path
    }

    DISPOSITIVOS_PENDENTES[ip] = dados

    salvo = salvar_json(
        ARQUIVO_PENDENTES,
        DISPOSITIVOS_PENDENTES
    )

    print(
        "==================================================",
        flush=True
    )

    print(
        "[NOVO ACESSO]",
        flush=True
    )

    print(
        f"IP: {ip}",
        flush=True
    )

    print(
        f"User-Agent: {user_agent}",
        flush=True
    )

    print(
        f"Rota: {request.path}",
        flush=True
    )

    print(
        f"Salvo: {salvo}",
        flush=True
    )

    print(
        "==================================================",
        flush=True
    )


# ============================================================
# /verAddr
# ============================================================

@app.route(
    "/verAddr",
    methods=[
        "GET",
        "POST",
        "OPTIONS"
    ]
)
def ver_addr():

    # Preflight
    if request.method == "OPTIONS":

        return "", 204

    ip = obter_ip()

    print(
        f"[VERADDR] requisição recebida de {ip}",
        flush=True
    )

    # ========================================================
    # APROVADO
    # ========================================================

    if ip in IPS_APROVADOS:

        print(
            f"[APROVADO] {ip}",
            flush=True
        )

        return jsonify({

            "status": "sucesso",

            "verAddr":
                "http://2.25.132.119:2223/"
                "aalto/false/false/false/false/"
                "false/false/false/false/"

        }), 200

    # ========================================================
    # NÃO APROVADO
    # ========================================================

    registrar_pendente(ip)

    # Sem JSON.
    # Sem texto.
    # Somente Not Found.
    return Response(
        status=404
    )


# ============================================================
# PAINEL HTML
# ============================================================

PAINEL = """

<!DOCTYPE html>

<html lang="pt-br">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>Painel de Acessos</title>

<style>

body {

    margin: 0;

    padding: 25px;

    font-family: Arial, sans-serif;

    background: #101010;

    color: white;

}

h1 {

    margin-bottom: 10px;

}

h2 {

    margin-top: 35px;

}

.info {

    background: #1b1b1b;

    padding: 15px;

    border-radius: 8px;

    margin-bottom: 20px;

}

table {

    width: 100%;

    border-collapse: collapse;

    margin-top: 15px;

}

th,
td {

    border: 1px solid #333;

    padding: 12px;

    text-align: left;

}

th {

    background: #242424;

}

td {

    background: #181818;

}

code {

    color: #00ff9d;

}

button,
a {

    display: inline-block;

    padding: 8px 13px;

    border-radius: 5px;

    border: 0;

    text-decoration: none;

    color: white;

    cursor: pointer;

}

.aprovar {

    background: #1f9d55;

}

.revogar {

    background: #d33;

}

form {

    margin-top: 15px;

}

input {

    padding: 10px;

    background: #202020;

    color: white;

    border: 1px solid #444;

    border-radius: 5px;

}

</style>

</head>


<body>


<h1>Painel de Controle</h1>


<div class="info">

<strong>Seu IP:</strong>

<code>
{{ meu_ip }}
</code>

<br><br>

<strong>Pendentes:</strong>

{{ pendentes|length }}

&nbsp;&nbsp;&nbsp;

<strong>Aprovados:</strong>

{{ aprovados|length }}

</div>


<h2>
Acessos aguardando aprovação
</h2>


<table>

<tr>

<th>IP</th>

<th>User-Agent / Dispositivo</th>

<th>Rota</th>

<th>Ação</th>

</tr>


{% for ip, dados in pendentes.items() %}

<tr>

<td>

<code>
{{ dados["ip"] }}
</code>

</td>


<td>

<code>
{{ dados["user_agent"] }}
</code>

</td>


<td>

<code>
{{ dados["rota"] }}
</code>

</td>


<td>

<a
    class="aprovar"
    href="{{ url_for('aprovar', ip=ip) }}"
>
APROVAR
</a>

</td>

</tr>


{% else %}

<tr>

<td colspan="4">

Nenhum acesso pendente.

</td>

</tr>

{% endfor %}

</table>


<h2>
Liberar IP manualmente
</h2>


<form
    action="{{ url_for('aprovar_manual') }}"
    method="POST"
>

<input
    type="text"
    name="ip"
    placeholder="Ex: 177.12.34.56"
    required
>

<button
    class="aprovar"
    type="submit"
>
APROVAR
</button>

</form>


<h2>
IPs aprovados
</h2>


<table>

<tr>

<th>IP</th>

<th>Ação</th>

</tr>


{% for ip in aprovados %}

<tr>

<td>

<code>
{{ ip }}
</code>

</td>

<td>

<a
    class="revogar"
    href="{{ url_for('revogar', ip=ip) }}"
>
REVOGAR
</a>

</td>

</tr>


{% else %}

<tr>

<td colspan="2">

Nenhum IP aprovado.

</td>

</tr>

{% endfor %}

</table>


</body>

</html>

"""


# ============================================================
# ADMIN
# ============================================================

@app.route("/admin")
@requer_admin
def painel_admin():

    return render_template_string(

        PAINEL,

        meu_ip=obter_ip(),

        pendentes=DISPOSITIVOS_PENDENTES,

        aprovados=sorted(
            IPS_APROVADOS
        )

    )


# ============================================================
# APROVAR
# ============================================================

@app.route("/admin/aprovar")
@requer_admin
def aprovar():

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    if not ip_valido(ip):

        return redirect(
            url_for("painel_admin")
        )

    IPS_APROVADOS.add(ip)

    DISPOSITIVOS_PENDENTES.pop(
        ip,
        None
    )

    save_ok_1 = salvar_json(
        ARQUIVO_APROVADOS,
        sorted(IPS_APROVADOS)
    )

    save_ok_2 = salvar_json(
        ARQUIVO_PENDENTES,
        DISPOSITIVOS_PENDENTES
    )

    print(
        f"[ADMIN] IP aprovado: {ip}",
        flush=True
    )

    print(
        f"[ADMIN] aprovados.json: {save_ok_1}",
        flush=True
    )

    print(
        f"[ADMIN] pendentes.json: {save_ok_2}",
        flush=True
    )

    return redirect(
        url_for("painel_admin")
    )


# ============================================================
# APROVAR MANUALMENTE
# ============================================================

@app.route(
    "/admin/aprovar_manual",
    methods=["POST"]
)
@requer_admin
def aprovar_manual():

    ip = request.form.get(
        "ip",
        ""
    ).strip()

    if ip_valido(ip):

        IPS_APROVADOS.add(ip)

        DISPOSITIVOS_PENDENTES.pop(
            ip,
            None
        )

        salvar_json(
            ARQUIVO_APROVADOS,
            sorted(IPS_APROVADOS)
        )

        salvar_json(
            ARQUIVO_PENDENTES,
            DISPOSITIVOS_PENDENTES
        )

        print(
            f"[ADMIN] IP aprovado manualmente: {ip}",
            flush=True
        )

    return redirect(
        url_for("painel_admin")
    )


# ============================================================
# REVOGAR
# ============================================================

@app.route("/admin/revogar")
@requer_admin
def revogar():

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    if ip in IPS_APROVADOS:

        IPS_APROVADOS.remove(ip)

        salvar_json(
            ARQUIVO_APROVADOS,
            sorted(IPS_APROVADOS)
        )

        print(
            f"[ADMIN] IP revogado: {ip}",
            flush=True
        )

    return redirect(
        url_for("painel_admin")
    )


# ============================================================
# ROTA DE TESTE DO SERVIDOR
# ============================================================

@app.route("/status")
def status():

    return jsonify({
        "online": True
    })


# ============================================================
# QUALQUER OUTRA ROTA
# ============================================================

@app.errorhandler(404)
def pagina_nao_encontrada(error):

    # Retorna somente 404,
    # sem mensagem personalizada.
    return Response(
        status=404
    )


# ============================================================
# INICIAR
# ============================================================

if __name__ == "__main__":

    print(
        "==========================================",
        flush=True
    )

    print(
        "SERVIDOR INICIADO",
        flush=True
    )

    print(
        f"PORTA: {PORT}",
        flush=True
    )

    print(
        "API: /verAddr",
        flush=True
    )

    print(
        "PAINEL: /admin",
        flush=True
    )

    print(
        "==========================================",
        flush=True
    )

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False
    )
