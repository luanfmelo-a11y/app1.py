from flask import Flask, jsonify, request, render_template_string, Response
from functools import wraps

app = Flask(__name__)

# =============================================================
# CONFIGURAÇÕES DE SEGURANÇA
# =============================================================
ADMIN_USER = "daviwld"            # Seu usuário de login
ADMIN_PASS = "luan4520r" # Sua senha
MAX_TENTATIVAS = 10             # Limite de erros de senha
# =============================================================

# ARMAZENAMENTO
IPS_APROVADOS = set()
DISPOSITIVOS_PENDENTES = {}
IPS_BANIDOS = set()
TENTATIVAS_ERRO_IP = {}

def obter_ip_real(req):
    """Captura o IP real do usuário, ignorando proxies do Render."""
    if req.headers.get('X-Forwarded-For'):
        return req.headers.get('X-Forwarded-For').split(',')[0].strip()
    return req.remote_addr

@app.before_request
def verificar_ip_banido():
    ip_cliente = obter_ip_real(request)
    if ip_cliente in IPS_BANIDOS:
        return jsonify({
            "status": "bloqueado",
            "mensagem": "Seu IP foi banido por tentativas incorretas de login."
        }), 403

def requer_autenticacao(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip_cliente = obter_ip_real(request)
        auth = request.authorization

        if auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASS:
            TENTATIVAS_ERRO_IP.pop(ip_cliente, None)
            return f(*args, **kwargs)

        if auth:
            erros = TENTATIVAS_ERRO_IP.get(ip_cliente, 0) + 1
            TENTATIVAS_ERRO_IP[ip_cliente] = erros
            if erros >= MAX_TENTATIVAS:
                IPS_BANIDOS.add(ip_cliente)
                return jsonify({"status": "banido", "mensagem": "IP banido por segurança."}), 403

        return Response(
            'Acesso negado. Credenciais invalidas.', 401,
            {'WWW-Authenticate': 'Basic realm="Painel Restrito"'}
        )
    return decorated

# -------------------------------------------------------------
# 1. API PÚBLICA (Para o Jogo / Script LUA)
# -------------------------------------------------------------
@app.route('/verAddr', methods=['GET', 'POST'])
def gateway_ver_addr():
    ip_cliente = obter_ip_real(request)
    user_agent = request.headers.get('User-Agent', 'Jogo/Script LUA')

    # Se o IP já estiver aprovado: entrega o JSON
    if ip_cliente in IPS_APROVADOS:
        return jsonify({
            "verAddr": "http://2.25.132.119:2223/aalto/false/false/false/false/false/false/false/false/"
        }), 200

    # Se não estiver aprovado: registra o IP na lista de pendentes
    DISPOSITIVOS_PENDENTES[ip_cliente] = {
        "ip": ip_cliente,
        "user_agent": user_agent
    }
    
    return jsonify({
        "status": "erro",
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
    </style>
</head>
<body>
    <h1>Painel de Aprovação de Acessos</h1>

    <!-- FORMULÁRIO DE APROVAÇÃO MANUAL POR IP -->
    <div class="box-manual">
        <h3>⚡ Liberar IP Manualmente</h3>
        <p style="color: #aaa; font-size: 14px;">Se o jogo não aparecer na lista abaixo, digite o IP do jogador para liberar diretamente:</p>
        <form action="/admin/aprovar_manual" method="GET">
            <input type="text" name="ip" placeholder="Ex: 177.12.34.56" required>
            <button type="submit" class="btn-manual">Liberar IP</button>
        </form>
    </div>
    
    <h2>⏳ Acessos Detectados Automaticamente (Pendentes)</h2>
    <table>
        <tr>
            <th>IP do Solicitante</th>
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
        <tr><td colspan="3">Nenhum acesso pendente registrado automaticamente no momento.</td></tr>
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
        aprovados=IPS_APROVADOS
    )

@app.route('/admin/aprovar')
@requer_autenticacao
def aprovar():
    ip = request.args.get('ip')
    if ip:
        IPS_APROVADOS.add(ip)
        DISPOSITIVOS_PENDENTES.pop(ip, None)
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/aprovar_manual')
@requer_autenticacao
def aprovar_manual():
    ip = request.args.get('ip', '').strip()
    if ip:
        IPS_APROVADOS.add(ip)
        DISPOSITIVOS_PENDENTES.pop(ip, None)
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
