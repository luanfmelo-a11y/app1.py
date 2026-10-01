from flask import Flask, jsonify, request, render_template_string, Response
from functools import wraps

app = Flask(__name__)

# =============================================================
# CONFIGURAÇÕES DE SEGURANÇA (ALTERE AQUI OS SEUS DADOS)
# =============================================================
ADMIN_USER = "daviwld"            # Seu nome de usuário
ADMIN_PASS = "luan4520r" # Sua senha secreta
MAX_TENTATIVAS = 10             # Limite de erros antes do banimento
# =============================================================

# --- BANCO DE DADOS EM MEMÓRIA ---
DISPOSITIVOS_APROVADOS = set()
DISPOSITIVOS_PENDENTES = {}

# Segurança e Banimento
IPS_BANIDOS = set()
TENTATIVAS_ERRO_IP = {}  # Formato: {"ip": quantidade_de_erros}


# --- MIDDLEWARE / VERIFICAÇÃO DE BANIMENTO ---
@app.before_request
def verificar_ip_banido():
    """Executado antes de qualquer requisição. Bloqueia IPs banidos imediatamente."""
    ip_cliente = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_cliente:
        # Pega o primeiro IP caso haja múltiplos no X-Forwarded-For
        ip_cliente = ip_cliente.split(',')[0].strip()

    if ip_cliente in IPS_BANIDOS:
        return jsonify({
            "status": "bloqueado",
            "mensagem": "Seu IP foi permanentemente banido por excesso de tentativas incorretas."
        }), 403


# --- DECORATOR DE AUTENTICAÇÃO COM CONTADOR DE ERROS ---
def requer_autenticacao(f):
    """Protege rotas com usuário/senha e aplica banimento após 10 erros."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip_cliente = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip_cliente:
            ip_cliente = ip_cliente.split(',')[0].strip()

        auth = request.authorization

        # Se as credenciais estiverem corretas: zera o contador de erros do IP e libera
        if auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASS:
            TENTATIVAS_ERRO_IP.pop(ip_cliente, None)
            return f(*args, **kwargs)

        # Se errou a senha ou não enviou credenciais:
        # Registra a tentativa com falha apenas se houver tentativa de auth
        if auth:
            erros_atuais = TENTATIVAS_ERRO_IP.get(ip_cliente, 0) + 1
            TENTATIVAS_ERRO_IP[ip_cliente] = erros_atuais

            print(f"[ALERTA SEGURANÇA] Tentativa incorreta de login do IP: {ip_cliente} ({erros_atuais}/{MAX_TENTATIVAS})")

            # Se atingiu ou passou de 10 erros, bane o IP
            if erros_atuais >= MAX_TENTATIVAS:
                IPS_BANIDOS.add(ip_cliente)
                print(f"[BANIMENTO] IP BANIDO POR EXCESSO DE TENTATIVAS: {ip_cliente}")
                return jsonify({
                    "status": "banido",
                    "mensagem": "IP banido por excesso de tentativas de login incorretas."
                }), 403

        # Solicita login e senha via browser
        return Response(
            'Acesso negado. Credenciais invalidas.', 401,
            {'WWW-Authenticate': 'Basic realm="Acesso Restrito ao Administrador"'}
        )
    return decorated


# -------------------------------------------------------------
# 1. API PÚBLICA (Para o jogo/script acessar)
# -------------------------------------------------------------
@app.route('/verAddr', methods=['GET', 'POST'])
def gateway_ver_addr():
    ip_cliente = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Desconhecido')
    id_dispositivo = f"{user_agent}"

    # Se já estiver aprovado no painel: entrega o JSON
    if id_dispositivo in DISPOSITIVOS_APROVADOS:
        return jsonify({
            "verAddr": "http://2.25.132.119:2223/aalto/false/false/false/false/false/false/false/false/"
        }), 200

    # Se não estiver aprovado: registra na lista de pendentes e bloqueia
    DISPOSITIVOS_PENDENTES[id_dispositivo] = {
        "ip": ip_cliente,
        "user_agent": user_agent
    }
    
    return jsonify({
        "status": "erro",
        "mensagem": "Acesso pendente de autorizacao."
    }), 403


# -------------------------------------------------------------
# 2. PAINEL DE ADMINISTRAÇÃO PROTEGIDO
# -------------------------------------------------------------
PAINEL_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Painel Seguro - verAddr</title>
    <style>
        body { font-family: sans-serif; background: #121212; color: #fff; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #222; }
        .btn { padding: 6px 12px; border-radius: 4px; text-decoration: none; color: #fff; font-weight: bold; }
        .btn-aprovar { background: #28a745; }
        .btn-revogar { background: #dc3545; }
        .btn-desbanir { background: #ffc107; color: #000; }
        .card-banidos { border: 1px solid #dc3545; padding: 15px; margin-top: 20px; border-radius: 6px; }
    </style>
</head>
<body>
    <h1>Painel de Controle Seguro</h1>
    
    <h2>Acessos Pendentes</h2>
    <table>
        <tr>
            <th>User-Agent</th>
            <th>IP</th>
            <th>Ação</th>
        </tr>
        {% for id, info in pendentes.items() %}
        <tr>
            <td><code>{{ info.user_agent }}</code></td>
            <td>{{ info.ip }}</td>
            <td><a href="/admin/aprovar?id={{ id }}" class="btn btn-aprovar">Aprovar</a></td>
        </tr>
        {% else %}
        <tr><td colspan="3">Nenhum acesso pendente.</td></tr>
        {% endfor %}
    </table>

    <h2>Acessos Aprovados</h2>
    <table>
        <tr>
            <th>User-Agent Autorizado</th>
            <th>Ação</th>
        </tr>
        {% for id in aprovados %}
        <tr>
            <td><code>{{ id }}</code></td>
            <td><a href="/admin/revogar?id={{ id }}" class="btn btn-revogar">Revogar</a></td>
        </tr>
        {% else %}
        <tr><td colspan="2">Nenhum dispositivo aprovado.</td></tr>
        {% endfor %}
    </table>

    <div class="card-banidos">
        <h2>IPs Banidos por Tentativas Incorretas</h2>
        <table>
            <tr>
                <th>Endereço IP Banido</th>
                <th>Ação</th>
            </tr>
            {% for ip in banidos %}
            <tr>
                <td><code>{{ ip }}</code></td>
                <td><a href="/admin/desbanir?ip={{ ip }}" class="btn btn-desbanir">Desbanir IP</a></td>
            </tr>
            {% else %}
            <tr><td colspan="2">Nenhum IP banido até o momento.</td></tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
"""

@app.route('/admin')
@requer_autenticacao
def painel_admin():
    return render_template_string(
        PAINEL_HTML, 
        pendentes=DISPOSITIVOS_PENDENTES, 
        aprovados=DISPOSITIVOS_APROVADOS,
        banidos=IPS_BANIDOS
    )

@app.route('/admin/aprovar')
@requer_autenticacao
def aprovar():
    dispositivo_id = request.args.get('id')
    if dispositivo_id:
        DISPOSITIVOS_APROVADOS.add(dispositivo_id)
        DISPOSITIVOS_PENDENTES.pop(dispositivo_id, None)
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/revogar')
@requer_autenticacao
def revogar():
    dispositivo_id = request.args.get('id')
    if dispositivo_id and dispositivo_id in DISPOSITIVOS_APROVADOS:
        DISPOSITIVOS_APROVADOS.remove(dispositivo_id)
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/desbanir')
@requer_autenticacao
def desbanir():
    ip = request.args.get('ip')
    if ip and ip in IPS_BANIDOS:
        IPS_BANIDOS.remove(ip)
        TENTATIVAS_ERRO_IP.pop(ip, None)
    return '<script>window.location.href="/admin";</script>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
