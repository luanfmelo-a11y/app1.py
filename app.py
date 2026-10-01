from flask import Flask, jsonify, request, render_template_string, Response
from functools import wraps
import time

app = Flask(__name__)

# =============================================================
# CONFIGURAÇÕES DE SEGURANÇA E MODO PROGRAMADOR
# =============================================================
ADMIN_USER = "admin"
ADMIN_PASS = "daviwld"
MASTER_KEY = "luan4520r"  # Use para liberar links rapidamente
MAX_TENTATIVAS = 10
# =============================================================

# BANCO DE DADOS GLOBAL (Persistente durante o ciclo de processo)
IPS_APROVADOS = set()
PENDENTES_LOG = []
IPS_BANIDOS = set()
TENTATIVAS_ERRO_IP = {}

def obter_ip_real():
    """Extrai com precisão o IP do jogador ignorando proxies do Render."""
    try:
        headers_ip = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP']
        for header in headers_ip:
            valor = request.headers.get(header)
            if valor:
                return valor.split(',')[0].strip()
        return request.remote_addr or "127.0.0.1"
    except Exception:
        return "127.0.0.1"

# LIBERAÇÃO DE CORS TOTAL PARA JOGOS / LUA / EXECUTÁVEIS
@app.after_request
def aplicar_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response

@app.before_request
def verificar_ip_banido():
    ip = obtaining_ip = obter_ip_real()
    if ip in IPS_BANIDOS:
        return jsonify({"status": "bloqueado", "erro": "IP banido por segurança."}), 403

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
                return jsonify({"status": "banido", "mensagem": "IP banido."}), 403

        return Response(
            'Acesso negado. Credenciais invalidas.', 401,
            {'WWW-Authenticate': 'Basic realm="Painel Restrito"'}
        )
    return decorated

# -------------------------------------------------------------
# 1. API PÚBLICA (USADA PELO JOGO / SCRIPT)
# -------------------------------------------------------------
@app.route('/verAddr', methods=['GET', 'POST', 'OPTIONS', 'PUT'])
def gateway_ver_addr():
    if request.method == 'OPTIONS':
        return '', 200

    ip_cliente = obter_ip_real()
    user_agent = request.headers.get('User-Agent', 'Desconhecido / Jogo')

    # REGISTRA TENTATIVA DE ACESSO NO LOG GLOBAL DE PENDENTES
    registro = {
        "ip": ip_cliente,
        "agent": user_agent,
        "hora": time.strftime('%H:%M:%S')
    }
    
    # Adiciona se ainda não constar nos pendentes
    if not any(item['ip'] == ip_cliente for item in PENDENTES_LOG):
        PENDENTES_LOG.insert(0, registro)
        if len(PENDENTES_LOG) > 50: # Mantém apenas os últimos 50
            PENDENTES_LOG.pop()

    # SE O IP JÁ TIVER SIDO APROVADO:
    if ip_cliente in IPS_APROVADOS:
        return jsonify({
            "status": "sucesso",
            "verAddr": "http://2.25.132.119:2223/aalto/false/false/false/false/false/false/false/false/"
        }), 200

    # SE NÃO ESTIVER APROVADO:
    return jsonify({
        "status": "pendente",
        "seu_ip": ip_cliente,
        "mensagem": f"IP {ip_cliente} aguardando aprovacao.",
        "link_liberacao_rapida": f"{request.host_url}master/liberar?key={MASTER_KEY}&ip={ip_cliente}"
    }), 403


# -------------------------------------------------------------
# 2. ROTA MESTRA DO PROGRAMADOR (LIBERAÇÃO DIRETA VIA URL/LINK)
# -------------------------------------------------------------
@app.route('/master/liberar', methods=['GET'])
def master_liberar():
    chave = request.args.get('key')
    ip = request.args.get('ip')

    if chave != MASTER_KEY:
        return jsonify({"status": "erro", "mensagem": "Chave mestra incorreta."}), 401

    if not ip:
        ip = obter_ip_real()

    IPS_APROVADOS.add(ip)
    
    # Remove do log de pendentes
    global PENDENTES_LOG
    PENDENTES_LOG = [item for item in PENDENTES_LOG if item['ip'] != ip]

    return f"""
    <div style="background: #121212; color: #00ff00; font-family: monospace; padding: 30px; text-align: center; font-size: 20px;">
        ✅ <strong>SUCESSO!</strong><br><br>
        O IP <u>{ip}</u> foi LIBERADO COM SUCESSO no sistema.<br>
        O jogo / script já pode acessar normalmente.
    </div>
    """


# -------------------------------------------------------------
# 3. PAINEL ADMINISTRATIVO COMPLETO
# -------------------------------------------------------------
PAINEL_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Mestre - verAddr</title>
    <style>
        body { font-family: monospace; background: #0e0e10; color: #e1e1e6; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 30px; background: #18181b; }
        th, td { border: 1px solid #27272a; padding: 12px; text-align: left; }
        th { background: #27272a; color: #a1a1aa; }
        .btn { padding: 8px 16px; border-radius: 4px; text-decoration: none; font-weight: bold; display: inline-block; }
        .btn-green { background: #22c55e; color: #000; }
        .btn-red { background: #ef4444; color: #fff; }
        .card { background: #18181b; border: 1px solid #27272a; padding: 20px; border-radius: 8px; margin-bottom: 25px; }
        input[type="text"] { padding: 10px; width: 280px; border-radius: 4px; border: 1px solid #3f3f46; background: #09090b; color: #fff; }
        button { padding: 10px 18px; background: #6366f1; color: #fff; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🛠️ Painel de Controle Definitivo</h1>

    <div class="card">
        <h3>⚡ Liberar Qualquer IP Manualmente</h3>
        <form action="/admin/aprovar_manual" method="GET">
            <input type="text" name="ip" placeholder="Digite o IP (Ex: 189.10.20.30)" required>
            <button type="submit">LIBERAR AGORA</button>
        </form>
    </div>

    <h2>⏳ Últimas Requisições Detectadas (Pendentes)</h2>
    <table>
        <tr>
            <th>Horário</th>
            <th>IP Solicitante</th>
            <th>Origem / User-Agent</th>
            <th>Ação</th>
        </tr>
        {% for item in pendentes %}
        <tr>
            <td>{{ item.hora }}</td>
            <td><code>{{ item.ip }}</code></td>
            <td><code>{{ item.agent }}</code></td>
            <td><a href="/admin/aprovar?ip={{ item.ip }}" class="btn btn-green">APROVAR IP</a></td>
        </tr>
        {% else %}
        <tr><td colspan="4">Nenhuma requisição pendente registrada até o momento.</td></tr>
        {% endfor %}
    </table>

    <h2>✅ IPs Aprovados Atualmente</h2>
    <table>
        <tr>
            <th>IP Liberado</th>
            <th>Ação</th>
        </tr>
        {% for ip in aprovados %}
        <tr>
            <td><code>{{ ip }}</code></td>
            <td><a href="/admin/revogar?ip={{ ip }}" class="btn btn-red">REVOGAR / BLOQUEAR</a></td>
        </tr>
        {% else %}
        <tr><td colspan="2">Nenhum IP aprovado.</td></tr>
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
        pendentes=PENDENTES_LOG,
        aprovados=IPS_APROVADOS
    )

@app.route('/admin/aprovar')
@requer_autenticacao
def aprovar():
    ip = request.args.get('ip')
    if ip:
        IPS_APROVADOS.add(ip)
        global PENDENTES_LOG
        PENDENTES_LOG = [item for item in PENDENTES_LOG if item['ip'] != ip]
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/aprovar_manual')
@requer_autenticacao
def aprovar_manual():
    ip = request.args.get('ip', '').strip()
    if ip:
        IPS_APROVADOS.add(ip)
        global PENDENTES_LOG
        PENDENTES_LOG = [item for item in PENDENTES_LOG if item['ip'] != ip]
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/revogar')
@requer_autenticacao
def revogar():
    ip = request.args.get('ip')
    if ip and ip in IPS_APROVADOS:
        IPS_APROVADOS.remove(ip)
    return '<script>window.location.href="/admin";</script>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
