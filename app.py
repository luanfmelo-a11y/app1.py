import os
import json
import ipaddress
from functools import wraps
from flask import Flask, request, jsonify, Response, render_template_string, redirect, url_for

app = Flask(__name__)

ADMIN_USER = os.environ.get("ADMIN_USER", "daviwld")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "luan4520r")
PORT = int(os.environ.get("PORT", 5000))

APPROVED_FILE = "aprovados.json"
PENDING_FILE = "pendentes.json"
BANNED_FILE = "banidos.json"


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def save_json(path, value):
    tmp = path + ".tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)

    os.replace(tmp, path)


IPS_APROVADOS = set(
    load_json(APPROVED_FILE, [])
)

DISPOSITIVOS_PENDENTES = load_json(
    PENDING_FILE, {}
)

IPS_BANIDOS = set(
    load_json(BANNED_FILE, [])
)

TENTATIVAS = {}


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_client_ip():

    xff = request.headers.get(
        "X-Forwarded-For",
        ""
    )

    if xff:

        candidate = xff.split(",")[0].strip()

        if valid_ip(candidate):
            return candidate

    xreal = request.headers.get(
        "X-Real-IP",
        ""
    ).strip()

    if valid_ip(xreal):
        return xreal

    remote = (
        request.remote_addr or ""
    ).strip()

    if valid_ip(remote):
        return remote

    return "0.0.0.0"


@app.after_request
def cors(response):

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


@app.before_request
def block_banned():

    if request.method == "OPTIONS":
        return None

    ip = get_client_ip()

    if ip in IPS_BANIDOS:
        return Response(status=404)

    return None


def admin_auth(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        auth = request.authorization
        ip = get_client_ip()

        if (
            auth
            and auth.username == ADMIN_USER
            and auth.password == ADMIN_PASS
        ):

            TENTATIVAS.pop(ip, None)

            return fn(*args, **kwargs)

        if auth:

            TENTATIVAS[ip] = (
                TENTATIVAS.get(ip, 0) + 1
            )

            if TENTATIVAS[ip] >= 10:

                IPS_BANIDOS.add(ip)

                save_json(
                    BANNED_FILE,
                    sorted(IPS_BANIDOS)
                )

                return Response(status=404)

        return Response(
            "Authentication required",
            401,
            {
                "WWW-Authenticate":
                'Basic realm="Painel"'
            }
        )

    return wrapper


# ============================================================
# API PRINCIPAL
# ============================================================

@app.route(
    "/verAddr",
    methods=["GET", "POST", "OPTIONS"]
)
def ver_addr():

    if request.method == "OPTIONS":
        return "", 204

    ip = get_client_ip()

    user_agent = request.headers.get(
        "User-Agent",
        "desconhecido"
    )

    print(
        f"[verAddr] IP={ip} "
        f"UA={user_agent}",
        flush=True
    )

    # ========================================================
    # IP JÁ APROVADO
    # ========================================================

    if ip in IPS_APROVADOS:

        return jsonify({
            "status": "sucesso",
            "verAddr":
                "http://2.25.132.119:2223/"
                "aalto/false/false/false/false/"
                "false/false/false/false/"
        }), 200

    # ========================================================
    # IP NÃO APROVADO
    # ========================================================

    DISPOSITIVOS_PENDENTES[ip] = {
        "ip": ip,
        "user_agent": user_agent
    }

    save_json(
        PENDING_FILE,
        DISPOSITIVOS_PENDENTES
    )

    print(
        f"[pendente] {ip}",
        flush=True
    )

    # Sem mensagem, exatamente como solicitado.
    return Response(status=404)


# ============================================================
# HTML DO PAINEL
# ============================================================

HTML = """
<!doctype html>

<html lang="pt-br">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>Painel</title>

<style>

body {
    font-family: Arial;
    background: #121212;
    color: #fff;
    padding: 20px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0 30px;
}

th,
td {
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

a,
button {
    padding: 8px 12px;
    border: 0;
    border-radius: 4px;
    color: #fff;
    text-decoration: none;
    cursor: pointer;
}

.ap {
    background: #28a745;
}

.rv {
    background: #dc3545;
}

input {
    padding: 8px;
    background: #222;
    color: #fff;
    border: 1px solid #444;
}

code {
    color: #00ff99;
}

</style>

</head>

<body>

<h1>Painel de acessos</h1>

<p>
Seu IP:
<code>{{ myip }}</code>
</p>

<h2>
Pendentes ({{ pending|length }})
</h2>

<table>

<tr>
<th>IP</th>
<th>User-Agent / dispositivo</th>
<th>Ação</th>
</tr>

{% for ip, info in pending.items() %}

<tr>

<td>
<code>{{ info["ip"] }}</code>
</td>

<td>
<code>{{ info["user_agent"] }}</code>
</td>

<td>

<a
    class="ap"
    href="{{ url_for('approve', ip=ip) }}"
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


<h2>
Aprovar manualmente
</h2>

<form
    action="{{ url_for('approve_manual') }}"
    method="post"
>

<input
    name="ip"
    placeholder="IP"
    required
>

<button
    class="ap"
    type="submit"
>
APROVAR
</button>

</form>


<h2>
Aprovados ({{ approved|length }})
</h2>

<table>

<tr>
<th>IP</th>
<th>Ação</th>
</tr>

{% for ip in approved %}

<tr>

<td>
<code>{{ ip }}</code>
</td>

<td>

<a
    class="rv"
    href="{{ url_for('revoke', ip=ip) }}"
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
# PAINEL
# ============================================================

@app.route("/admin")
@admin_auth
def admin():

    return render_template_string(
        HTML,
        myip=get_client_ip(),
        pending=DISPOSITIVOS_PENDENTES,
        approved=sorted(IPS_APROVADOS)
    )


# ============================================================
# APROVAR
# ============================================================

@app.route("/admin/aprovar")
@admin_auth
def approve():

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    if valid_ip(ip):

        IPS_APROVADOS.add(ip)

        DISPOSITIVOS_PENDENTES.pop(
            ip,
            None
        )

        save_json(
            APPROVED_FILE,
            sorted(IPS_APROVADOS)
        )

        save_json(
            PENDING_FILE,
            DISPOSITIVOS_PENDENTES
        )

    return redirect(
        url_for("admin")
    )


# ============================================================
# APROVAR MANUALMENTE
# ============================================================

@app.route(
    "/admin/aprovar_manual",
    methods=["POST"]
)
@admin_auth
def approve_manual():

    ip = request.form.get(
        "ip",
        ""
    ).strip()

    if valid_ip(ip):

        IPS_APROVADOS.add(ip)

        DISPOSITIVOS_PENDENTES.pop(
            ip,
            None
        )

        save_json(
            APPROVED_FILE,
            sorted(IPS_APROVADOS)
        )

        save_json(
            PENDING_FILE,
            DISPOSITIVOS_PENDENTES
        )

    return redirect(
        url_for("admin")
    )


# ============================================================
# REVOGAR
# ============================================================

@app.route("/admin/revogar")
@admin_auth
def revoke():

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    if ip in IPS_APROVADOS:

        IPS_APROVADOS.remove(ip)

        save_json(
            APPROVED_FILE,
            sorted(IPS_APROVADOS)
        )

    return redirect(
        url_for("admin")
    )


# ============================================================
# ROTA RAIZ
# ============================================================

@app.route("/")
def root():

    return Response(status=404)


# ============================================================
# INICIAR
# ============================================================

if __name__ == "__main__":

    print(
        f"Servidor iniciado na porta {PORT}",
        flush=True
    )

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False
    )
