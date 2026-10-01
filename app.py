import os
import json
import ipaddress
from functools import wraps

from flask import (
    Flask,
    jsonify,
    request,
    render_template_string,
    Response,
    redirect,
    url_for
)

app = Flask(__name__)

# =============================================================
# CONFIGURAÇÕES
# =============================================================

ADMIN_USER = os.environ.get("ADMIN_USER", "daviwld")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "luan4520r")

MAX_TENTATIVAS = 10

ARQUIVO_APROVADOS = "aprovados.json"
ARQUIVO_PENDENTES = "pendentes.json"
ARQUIVO_BANIDOS = "banidos.json"

# =============================================================
# FUNÇÕES DE ARQUIVO
# =============================================================

def carregar_json(arquivo, padrao):
    if not os.path.exists(arquivo):
        return padrao

    try:
        with open(arquivo, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return padrao


def salvar_json(arquivo, dados):
    try:
        with open(arquivo, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        return True
    except OSError as e:
        print(f"Erro ao salvar {arquivo}: {e}")
        return False


# =============================================================
# DADOS
# =============================================================

IPS_APROVADOS = set(
    carregar_json(ARQUIVO_APROVADOS, [])
)

DISPOSITIVOS_PENDENTES = carregar_json(
    ARQUIVO_PENDENTES, {}
)

IPS_BANIDOS = set(
    carregar_json(ARQUIVO_BANIDOS, [])
)

TENTATIVAS_ERRO_IP = {}


# =============================================================
# IP
# =============================================================

def obter_ip_real():
    """
    Obtém o IP da conexão.

    ATENÇÃO:
    X-Forwarded-For só deve ser confiado quando vier
    de um proxy reverso que você controla.
    """

    # Se estiver usando um proxy confiável,
    # você pode habilitar esta opção.
    proxy_ip = request.headers.get("X-Real-IP")

    if proxy_ip:
        ip = proxy_ip.strip()
    else:
        ip = request.remote_addr

    if not ip:
        return "0.0.0.0"

    # Validação
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return "0.0.0.0"


def ip_valido(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# =============================================================
# CORS
# =============================================================

@app.after_request
def aplicar_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"

    return response


# =============================================================
# VERIFICAR IP BANIDO
# =============================================================

@app.before_request
def verificar_ip_banido():

    # Não bloqueia OPTIONS
    if request.method == "OPTIONS":
        return None

    ip = obter_ip_real()

    if ip in IPS_BANIDOS:
        return jsonify({
            "status": "bloqueado",
            "mensagem": "IP banido."
        }), 403

    return None


# =============================================================
# AUTENTICAÇÃO ADMIN
# =============================================================

def requer_autenticacao(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        ip = obter_ip_real()
        auth = request.authorization

        if (
            auth
            and auth.username == ADMIN_USER
            and auth.password == ADMIN_PASS
        ):
            TENTATIVAS_ERRO_IP.pop(ip, None)

            return f(*args, **kwargs)

        if auth:

            erros = TENTATIVAS_ERRO_IP.get(ip, 0) + 1
            TENTATIVAS_ERRO_IP[ip] = erros

            if erros >= MAX_TENTATIVAS:

                IPS_BANIDOS.add(ip)
                salvar_json(
                    ARQUIVO_BANIDOS,
                    list(IPS_BANIDOS)
                )

                return jsonify({
                    "status": "banido",
                    "mensagem": "IP banido por excesso de tentativas."
                }), 403

        return Response(
            "Acesso negado. Credenciais invalidas.",
            401,
            {
                "WWW-Authenticate":
                'Basic realm="Painel Restrito"'
            }
        )

    return decorated


# =============================================================
# API /verAddr
# =============================================================

@app.route(
    "/verAddr",
    methods=["GET", "POST", "OPTIONS"]
)
def gateway_ver_addr():

    if request.method == "OPTIONS":
        return "", 200

    ip_cliente = obter_ip_real()

    user_agent = request.headers.get(
        "User-Agent",
        "Desconhecido"
    )

    print(
        f"[VERADDR] IP={ip_cliente} "
        f"USER_AGENT={user_agent}"
    )

    # ---------------------------------------------------------
    # IP APROVADO
    # ---------------------------------------------------------

    if ip_cliente in IPS_APROVADOS:

        print(
            f"[APROVADO] {ip_cliente}"
        )

        return jsonify({
            "status": "sucesso",
            "verAddr":
                "http://2.25.132.119:2223/"
                "aalto/false/false/false/false/"
                "false/false/false/false/"
        }), 200

    # ---------------------------------------------------------
    # IP NÃO APROVADO
    # ---------------------------------------------------------

    DISPOSITIVOS_PENDENTES[ip_cliente] = {
        "ip": ip_cliente,
        "user_agent": user_agent
    }

    salvar_json(
        ARQUIVO_PENDENTES,
        DISPOSITIVOS_PENDENTES
    )

    print(
        f"[PENDENTE] Novo acesso: {ip_cliente}"
    )

    return jsonify({
        "status": "erro",
        "ip_detectado": ip_cliente,
        "mensagem":
            f"Acesso pendente de autorizacao "
            f"para o IP: {ip_cliente}"
    }), 403


# =============================================================
# PAINEL
# =============================================================

PAINEL_HTML = """
<!DOCTYPE html>

<html lang="pt-br">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>Painel Admin</title>

<style>

body {
    font-family: Arial, sans-serif;
    background: #121212;
    color: white;
    padding: 20px;
}

h1, h2 {
    color: white;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    margin-bottom: 30px;
}

th, td {
    border: 1px solid #333;
    padding: 10px;
    text-align: left;
}

th {
    background: #222;
}

td {
    background: #181818;
}

.btn {
    padding: 8px 14px;
    border-radius: 4px;
    text-decoration: none;
    color: white;
    font-weight: bold;
    display: inline-block;
}

.btn-aprovar {
    background: #28a745;
}

.btn-revogar {
    background: #dc3545;
}

.btn-banir {
    background: #6f42c1;
}

.btn-manual {
    background: #007bff;
    border: none;
    padding: 8px 14px;
    color: white;
    font-weight: bold;
    cursor: pointer;
    border-radius: 4px;
}

input[type="text"] {
    padding: 8px;
    width: 250px;
    border-radius: 4px;
    border: 1px solid #444;
    background: #222;
    color: white;
}

.box-manual {
    background: #1e1e1e;
    padding: 15px;
    border-radius: 6px;
    margin-bottom: 30px;
    border: 1px solid #333;
}

.status {
    background: #1e1e1e;
    padding: 12px;
    border-radius: 5px;
    margin-bottom: 20px;
}

code {
    color: #00ff99;
}

</style>

</head>

<body>

<h1>Painel de Controle</h1>

<div class="status">

<strong>Seu IP:</strong>

<code>{{ seu_ip }}</code>

<br><br>

<strong>Pendentes:</strong>
{{ pendentes|length }}

&nbsp;&nbsp;

<strong>Aprovados:</strong>
{{ aprovados|length }}

</div>


<!-- =====================================================
LIBERAÇÃO MANUAL
===================================================== -->

<div class="box-manual">

<h3>⚡ Liberar IP Manualmente</h3>

<form
    action="/admin/aprovar_manual"
    method="POST"
>

<input
    type="text"
    name="ip"
    placeholder="Ex: 177.12.34.56"
    required
>

<button
    type="submit"
    class="btn-manual"
>
Liberar IP
</button>

</form>

</div>


<!-- =====================================================
PENDENTES
===================================================== -->

<h2>⏳ Acessos Pendentes</h2>

<table>

<tr>

<th>IP</th>

<th>Dispositivo / User-Agent</th>

<th>Ação</th>

</tr>

{% for ip, info in pendentes.items() %}

<tr>

<td>
<code>{{ info.ip }}</code>
</td>

<td>
<code>{{ info.user_agent }}</code>
</td>

<td>

<a
    href="/admin/aprovar?ip={{ ip }}"
    class="btn btn-aprovar"
>
APROVAR
</a>

</td>

</tr>

{% else %}

<tr>

<td colspan="3">
Nenhum acesso pendente.
</td>

</tr>

{% endfor %}

</table>


<!-- =====================================================
APROVADOS
===================================================== -->

<h2>✅ IPs Aprovados</h2>

<table>

<tr>

<th>IP</th>

<th>Ação</th>

</tr>

{% for ip in aprovados %}

<tr>

<td>
<code>{{ ip }}</code>
</td>

<td>

<a
    href="/admin/revogar?ip={{ ip }}"
    class="btn btn-revogar"
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


# =============================================================
# ROTA ADMIN
# =============================================================

@app.route("/admin")
@requer_autenticacao
def painel_admin():

    return render_template_string(
        PAINEL_HTML,
        pendentes=DISPOSITIVOS_PENDENTES,
        aprovados=sorted(IPS_APROVADOS),
        seu_ip=obter_ip_real()
    )


# =============================================================
# APROVAR IP
# =============================================================

@app.route("/admin/aprovar")
@requer_autenticacao
def aprovar():

    ip = request.args.get("ip", "").strip()

    if ip_valido(ip):

        IPS_APROVADOS.add(ip)

        DISPOSITIVOS_PENDENTES.pop(
            ip,
            None
        )

        salvar_json(
            ARQUIVO_APROVADOS,
            list(IPS_APROVADOS)
        )

        salvar_json(
            ARQUIVO_PENDENTES,
            DISPOSITIVOS_PENDENTES
        )

        print(
            f"[ADMIN] IP aprovado: {ip}"
        )

    return redirect(
        url_for("painel_admin")
    )


# =============================================================
# APROVAÇÃO MANUAL
# =============================================================

@app.route(
    "/admin/aprovar_manual",
    methods=["POST"]
)
@requer_autenticacao
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
            list(IPS_APROVADOS)
        )

        salvar_json(
            ARQUIVO_PENDENTES,
            DISPOSITIVOS_PENDENTES
        )

        print(
            f"[ADMIN] IP aprovado manualmente: {ip}"
        )

    return redirect(
        url_for("painel_admin")
    )


# =============================================================
# REVOGAR
# =============================================================

@app.route("/admin/revogar")
@requer_autenticacao
def revogar():

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    if ip in IPS_APROVADOS:

        IPS_APROVADOS.remove(ip)

        salvar_json(
            ARQUIVO_APROVADOS,
            list(IPS_APROVADOS)
        )

        print(
            f"[ADMIN] IP revogado: {ip}"
        )

    return redirect(
        url_for("painel_admin")
    )


# =============================================================
# TESTE DA API
# =============================================================

@app.route("/")
def inicio():

    return jsonify({
        "status": "online",
        "api": "/verAddr",
        "painel": "/admin"
    })


# =============================================================
# INICIAR SERVIDOR
# =============================================================

if __name__ == "__main__":

    print("=" * 50)
    print("SERVIDOR INICIADO")
    print("API:    /verAddr")
    print("PAINEL: /admin")
    print("=" * 50)

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False
    )
