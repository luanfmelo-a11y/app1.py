import os
import time
import hmac
from functools import wraps
from threading import Lock

from flask import Flask, jsonify, request, render_template_string, Response, redirect

app = Flask(__name__)

# =============================================================
# CONFIGURAÇÕES
# (no Render, prefira definir ADMIN_USER / ADMIN_PASS como
#  variáveis de ambiente em vez de deixar a senha no código)
# =============================================================
ADMIN_USER = os.environ.get("ADMIN_USER", "daviwld")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "luan4520r")
MAX_TENTATIVAS = 10
MAX_VISITANTES = 1000
# =============================================================

LOCK = Lock()
VISITANTES = {}          # ip -> dados do visitante
IPS_BANIDOS = set()
TENTATIVAS_ERRO_IP = {}


def obter_ip_real():
    """Extrai o IP do cliente considerando o proxy do Render."""
    for header in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"):
        valor = request.headers.get(header)
        if valor:
            return valor.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def agora():
    return time.strftime("%d/%m/%Y %H:%M:%S")


@app.after_request
def aplicar_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response


@app.before_request
def registrar_visitante():
    """Registra os dados de quem acessa qualquer rota (exceto o painel)."""
    ip = obter_ip_real()

    if ip in IPS_BANIDOS:
        return jsonify({"status": "bloqueado"}), 403

    if request.path.startswith("/admin"):
        return None

    with LOCK:
        v = VISITANTES.get(ip)
        if v is None:
            if len(VISITANTES) >= MAX_VISITANTES:
                # descarta o mais antigo para não crescer sem limite
                mais_antigo = min(VISITANTES, key=lambda k: VISITANTES[k]["ts"])
                VISITANTES.pop(mais_antigo)
            v = {"primeiro": agora(), "acessos": 0}
            VISITANTES[ip] = v

        v["ultimo"] = agora()
        v["ts"] = time.time()
        v["acessos"] += 1
        v["agent"] = request.headers.get("User-Agent", "Desconhecido")
        v["idioma"] = request.headers.get("Accept-Language", "-")
        v["origem"] = request.headers.get("Referer", "-")
        v["metodo"] = request.method
        v["rota"] = request.full_path.rstrip("?")
    return None


def requer_autenticacao(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = obter_ip_real()
        auth = request.authorization

        if auth:
            user_ok = hmac.compare_digest(auth.username or "", ADMIN_USER)
            pass_ok = hmac.compare_digest(auth.password or "", ADMIN_PASS)
            if user_ok and pass_ok:
                TENTATIVAS_ERRO_IP.pop(ip, None)
                return f(*args, **kwargs)

            erros = TENTATIVAS_ERRO_IP.get(ip, 0) + 1
            TENTATIVAS_ERRO_IP[ip] = erros
            if erros >= MAX_TENTATIVAS:
                IPS_BANIDOS.add(ip)
                return jsonify({"status": "banido"}), 403

        return Response(
            "Acesso negado.", 401,
            {"WWW-Authenticate": 'Basic realm="Painel Restrito"'},
        )
    return decorated


# -------------------------------------------------------------
# ROTA PÚBLICA: apenas registra o visitante (feito no before_request)
# -------------------------------------------------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "OPTIONS"])
def catch_all(path):
    if request.method == "OPTIONS":
        return "", 200
    return jsonify({"status": "ok"}), 200


# -------------------------------------------------------------
# PAINEL ADMINISTRATIVO
# -------------------------------------------------------------
PAINEL_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel - Visitantes</title>
    <style>
        body { font-family: monospace; background: #0e0e10; color: #e1e1e6; padding: 20px; }
        .wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background: #18181b; }
        th, td { border: 1px solid #27272a; padding: 10px; text-align: left; font-size: 13px; }
        th { background: #27272a; color: #a1a1aa; }
        button { padding: 10px 18px; background: #ef4444; color: #fff; border: none;
                 border-radius: 4px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <h1>📋 Visitantes ({{ visitantes|length }})</h1>
    <form action="/admin/limpar" method="POST"
          onsubmit="return confirm('Apagar todos os registros?')">
        <button type="submit">LIMPAR REGISTROS</button>
    </form>

    <div class="wrap">
    <table>
        <tr>
            <th>Último acesso</th>
            <th>Primeiro acesso</th>
            <th>IP</th>
            <th>Acessos</th>
            <th>Método / Rota</th>
            <th>User-Agent</th>
            <th>Idioma</th>
            <th>Origem</th>
        </tr>
        {% for ip, v in visitantes %}
        <tr>
            <td>{{ v.ultimo }}</td>
            <td>{{ v.primeiro }}</td>
            <td><code>{{ ip }}</code></td>
            <td>{{ v.acessos }}</td>
            <td>{{ v.metodo }} {{ v.rota }}</td>
            <td><code>{{ v.agent }}</code></td>
            <td>{{ v.idioma }}</td>
            <td>{{ v.origem }}</td>
        </tr>
        {% else %}
        <tr><td colspan="8">Nenhum acesso registrado até o momento.</td></tr>
        {% endfor %}
    </table>
    </div>
</body>
</html>
"""


@app.route("/admin")
@requer_autenticacao
def painel_admin():
    with LOCK:
        lista = sorted(VISITANTES.items(), key=lambda kv: kv[1]["ts"], reverse=True)
    return render_template_string(PAINEL_HTML, visitantes=lista)


@app.route("/admin/limpar", methods=["POST"])
@requer_autenticacao
def limpar():
    with LOCK:
        VISITANTES.clear()
    return redirect("/admin")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
