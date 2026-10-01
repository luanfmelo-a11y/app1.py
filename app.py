import os
import json
from flask import Flask, jsonify, request, render_template_string, Response
from functools import wraps

app = Flask(__name__)

# =============================================================
# CONFIGURAÇÕES DE SEGURANÇA
# =============================================================
ADMIN_USER = "daviwld"            # Seu usuário para acessar o painel
ADMIN_PASS = "luan4520r" # Sua senha para acessar o painel
MAX_TENTATIVAS = 10             # Tentativas de senha errada antes do ban
ARQUIVO_DADOS = "aprovados.json"
# =============================================================

# --- CARREGAR E SALVAR DADOS EM ARQUIVO LOCAL ---
def carregar_aprovados():
    if os.path.exists(ARQUIVO_DADOS):
        try:
            with open(ARQUIVO_DADOS, 'r') as f:
                return set(json.load(f))
        except:
            return set()
    return set()

def salvar_aprovados():
    try:
        with open(ARQUIVO_DADOS, 'w') as f:
            json.dump(list(IPS_APROVADOS), f)
    except Exception as e:
        print(f"Erro ao salvar arquivo: {e}")

IPS_APROVADOS = carregar_aprovados()
DISPOSITIVOS_PENDENTES = {}
IPS_BANIDOS = set()
TENTATIVAS_ERRO_IP = {}


def obter_ip_real():
    """Captura o IP real garantindo que requisições do jogo não quebrem."""
    try:
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        if request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP').strip()
        return request.remote_addr or "0.0.0.0"
    except:
        return "0.0.0.0"


# CORS MANUAL: Garante que scripts LUA / jogos consigam conectar sem bloqueio
@app.after_request
def aplicar_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.before_request
def verificar_ip_banido():
    ip = obter_ip_real()
    if ip in IPS_BANIDOS:
        return jsonify({
            "status": "bloqueado",
            "mensagem": "IP banido."
        }), 403


def requer_autenticacao(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = obter_ip_real()
        auth = request.authorization

        if auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASS:
            TENTATIVAS_ERRO_IP.pop(ip, None)
            return f(*args, **kwargs)

        if auth:
            erros = TENTATIVAS_ERRO_IP.get(ip, 0) + 1
            TENTATIVAS_ERRO_IP[ip] = erros
            if erros >= MAX_TENTATIVAS:
                IPS_BANIDOS.add(ip)
                return jsonify({"status": "banido", "mensagem": "IP banido por segurança."}), 403

        return Response(
            'Acesso negado. Credenciais invalidas.', 401,
            {'WWW-Authenticate': 'Basic realm="Painel Restrito"'}
        )
    return decorated


# -------------------------------------------------------------
# 1. API PÚBLICA (Para o Jogo / Script LUA)
# -------------------------------------------------------------
@app.route('/verAddr', methods=['GET', 'POST', 'OPTIONS'])
def gateway_ver_addr():
    if request.method == 'OPTIONS':
        return '', 200

    ip_cliente = obter_ip_real()
    user_agent = request.headers.get('User-Agent', 'Script LUA / Jogo')

    # Se o IP já estiver na lista de aprovados: entrega o JSON do verAddr
    if ip_cliente in IPS_APROVADOS:
        return jsonify({
            "status": "sucesso",
            "verAddr": "http://2.25.132.119:2223/aalto/false/false/false/false/false/false/false/false/"
        }), 200

    # Registra o IP na lista de pendentes para aparecer no painel
    DISPOSITIVOS_PENDENTES[ip_cliente] = {
        "ip": ip_cliente,
        "user_agent": user_agent
    }

    return jsonify({
        "status": "erro",
        "ip_detectado": ip_cliente,
        "mensagem": f"Acesso pendente de autorizacao para o IP: {ip_cliente}"
    }), 403


# -------------------------------------------------------------
# 2. PAINEL ADMINISTRATIVO
# -------------------------------------------------------------
PAINEL_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Admin - verAddr</title>
    <style>
        body { font-family: Arial, sans-serif; background: #121212; color: #fff; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 30px; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #222; }
        .btn { padding: 8px 14px; border-radius: 4px; text-decoration: none; color: #fff; font-weight: bold; display: inline-block; }
        .btn-aprovar { background: #28a745; }
        .btn-revogar { background: #dc3545; }
        .btn-manual { background: #007bff; border: none; padding: 8px 14px; color: #fff; font-weight: bold; cursor: pointer; border-radius: 4px; }
        input[type="text"] { padding: 8px; width: 250px; border-radius: 4px; border: 1px solid #444; background: #222; color: #fff; }
        .box-manual { background: #1e1e1e; padding: 15px; border-radius: 6px; margin-bottom: 30px; border: 1px solid #333; }
        .meu-ip { background: #333; padding: 10px; border-radius: 4px; display: inline-block; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Painel de Controle de Acessos</h1>

    <div class="meu-ip">
        🌐 <strong>Seu IP Atual de Acesso:</strong> <code>{{ seu_ip }}</code>
    </div>

    <!-- FORMULÁRIO DE LIBERAÇÃO MANUAL DE IP -->
    <div class="box-manual">
        <h3>⚡ Liberar IP Manualmente</h3>
        <p style="color: #aaa; font-size: 14px;">Copie o IP retornado na resposta do jogo/script e cole abaixo para liberar instantaneamente:</p>
        <form action="/admin/aprovar_manual" method="GET">
            <input type="text" name="ip" placeholder="Ex: 177.12.34.56" required>
            <button type="submit" class="btn-manual">Liberar IP</button>
        </form>
    </div>
    
    <h2>⏳ Acessos Pendentes (Detectados Automaticamente)</h2>
    <table>
        <tr>
            <th>IP Solicitante</th>
            <th>Agente / Origem</th>
            <th>Ação</th>
        </tr>
        {% for ip, info in pendentes.items() %}
        <tr>
            <td><code>{{ info.ip }}</code></td>
            <td><code>{{ info.user_agent }}</code></td>
            <td><a href="/admin/aprovar?ip={{ ip }}" class="btn btn-aprovar">APROVAR</a></td>
        </tr>
        {% else %}
        <tr><td colspan="3">Nenhum acesso pendente gravado recentemente.</td></tr>
        {% endfor %}
    </table>

    <h2>✅ IPs Aprovados / Liberados</h2>
    <table>
        <tr>
            <th>IP Autorizado</th>
            <th>Ação</th>
        </tr>
        {% for ip in aprovados %}
        <tr>
            <td><code>{{ ip }}</code></td>
            <td><a href="/admin/revogar?ip={{ ip }}" class="btn btn-revogar">Revogar / Bloquear</a></td>
        </tr>
        {% else %}
        <tr><td colspan="2">Nenhum IP aprovado no momento.</td></tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route('/admin')
@requer_autenticacao
def painel_admin():
    return render_template_string(
        PAINEL_HTML, 
        pendentes=DISPOSITIVOS_PENDENTES, 
        aprovados=IPS_APROVADOS,
        seu_ip=obter_ip_real()
    )

@app.route('/admin/aprovar')
@requer_autenticacao
def aprovar():
    ip = request.args.get('ip')
    if ip:
        IPS_APROVADOS.add(ip)
        DISPOSITIVOS_PENDENTES.pop(ip, None)
        salvar_aprovados()
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/aprovar_manual')
@requer_autenticacao
def aprovar_manual():
    ip = request.args.get('ip', '').strip()
    if ip:
        IPS_APROVADOS.add(ip)
        DISPOSITIVOS_PENDENTES.pop(ip, None)
        salvar_aprovados()
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/revogar')
@requer_autenticacao
def revogar():
    ip = request.args.get('ip')
    if ip and ip in IPS_APROVADOS:
        IPS_APROVADOS.remove(ip)
        salvar_aprovados()
    return '<script>window.location.href="/admin";</script>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
