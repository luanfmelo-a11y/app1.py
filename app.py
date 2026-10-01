import os
import time
from threading import Lock
from flask import Flask, Response, request, render_template_string, jsonify

app = Flask(__name__)

LOCK = Lock()
VISITANTES = {}
MAX_REGISTROS = 1000

# Resposta JSON idêntica ao padrão aceito nativamente
JSON_RESPOSTA = '{"status":"sucesso","verAddr":"http://2.25.132.119:2223/aalto/false/false/false/false/false/false/false/false/"}'

def obter_ip_real():
    for header in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        valor = request.headers.get(header)
        if valor:
            return valor.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def agora():
    return time.strftime("%d/%m/%Y %H:%M:%S")

@app.before_request
def registrar_acesso():
    if request.path.startswith("/admin"):
        return None

    ip = obter_ip_real()
    
    with LOCK:
        v = VISITANTES.get(ip)
        if v is None:
            if len(VISITANTES) >= MAX_REGISTROS:
                mais_antigo = min(VISITANTES, key=lambda k: VISITANTES[k]["ts"])
                VISITANTES.pop(mais_antigo)
            v = {"primeiro": agora(), "acessos": 0}
            VISITANTES[ip] = v

        v["ultimo"] = agora()
        v["ts"] = time.time()
        v["acessos"] += 1
        v["agent"] = request.headers.get("User-Agent", "Desconhecido")
        v["metodo"] = request.method
        v["rota"] = request.full_path.rstrip("?")
    return None

# -------------------------------------------------------------
# ROTA CRÍTICA PARA O JOGO (/verAddr)
# -------------------------------------------------------------
@app.route("/verAddr", methods=["GET", "POST", "OPTIONS"])
def gateway_ver_addr():
    # Retorna resposta JSON bruta para evitar falhas de parseamento no cliente
    res = Response(JSON_RESPOSTA, status=200, mimetype="application/json")
    res.headers["Access-Control-Allow-Origin"] = "*"
    res.headers["Access-Control-Allow-Headers"] = "*"
    res.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    res.headers["Content-Type"] = "application/json; charset=utf-8"
    return res

# -------------------------------------------------------------
# PAINEL ADMINISTRATIVO (/admin)
# -------------------------------------------------------------
PAINEL_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel de Monitoramento</title>
    <style>
        body { font-family: monospace; background: #0e0e10; color: #e1e1e6; padding: 20px; }
        .wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background: #18181b; }
        th, td { border: 1px solid #27272a; padding: 10px; text-align: left; font-size: 13px; }
        th { background: #27272a; color: #a1a1aa; }
        .btn-limpar { padding: 8px 14px; background: #ef4444; color: #fff; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <h1>📊 IPs Registrados no Servidor ({{ visitantes|length }})</h1>
    
    <form action="/admin/limpar" method="POST" onsubmit="return confirm('Limpar histórico?')">
        <button type="submit" class="btn-limpar">LIMPAR REGISTROS</button>
    </form>

    <div class="wrap">
    <table>
        <tr>
            <th>Último Acesso</th>
            <th>Primeiro Acesso</th>
            <th>IP do Dispositivo</th>
            <th>Acessos</th>
            <th>Rota Acessada</th>
            <th>User-Agent</th>
        </tr>
        {% for ip, v in visitantes %}
        <tr>
            <td>{{ v.ultimo }}</td>
            <td>{{ v.primeiro }}</td>
            <td><code>{{ ip }}</code></td>
            <td>{{ v.acessos }}</td>
            <td><code>{{ v.metodo }} {{ v.rota }}</code></td>
            <td><code>{{ v.agent }}</code></td>
        </tr>
        {% else %}
        <tr><td colspan="6">Nenhum acesso registrado até o momento.</td></tr>
        {% endfor %}
    </table>
    </div>
</body>
</html>
"""

@app.route("/admin", methods=["GET"])
def painel_admin():
    with LOCK:
        lista = sorted(VISITANTES.items(), key=lambda kv: kv[1]["ts"], reverse=True)
    return render_template_string(PAINEL_HTML, visitantes=lista)

@app.route("/admin/limpar", methods=["POST"])
def limpar():
    with LOCK:
        VISITANTES.clear()
    return render_template_string('<script>window.location.href="/admin";</script>')

@app.route("/", methods=["GET", "POST"])
def index():
    return jsonify({"status": "online"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
