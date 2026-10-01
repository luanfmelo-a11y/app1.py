from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)

# --- LISTAS DE AUTORIZAÇÃO (Em memória) ---
DISPOSITIVOS_APROVADOS = set()
DISPOSITIVOS_PENDENTES = {}

# -------------------------------------------------------------
# 1. API PÚBLICA (Para o cliente/jogo acessar)
# -------------------------------------------------------------
@app.route('/verAddr', methods=['GET', 'POST'])
def gateway_ver_addr():
    ip_cliente = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Desconhecido')
    id_dispositivo = f"{user_agent}"

    # Se já estiver aprovado no painel: entrega o JSON
    if id_dispositivo in DISPOSITIVOS_APROVADOS:
        print(f"[LIBERADO] Acesso autorizado para: {id_dispositivo}")
        return jsonify({
            "verAddr": "http://2.25.132.119:2223/aalto/false/false/false/false/false/false/false/false/"
        }), 200

    # Se não estiver aprovado: registra na lista de pendentes e bloqueia
    DISPOSITIVOS_PENDENTES[id_dispositivo] = {
        "ip": ip_cliente,
        "user_agent": user_agent
    }
    
    print(f"[BLOQUEADO] Novo acesso registrado aguardando aprovação: {id_dispositivo}")
    
    return jsonify({
        "status": "erro",
        "mensagem": "Acesso pendente de autorizacao pelo administrador."
    }), 403


# -------------------------------------------------------------
# 2. PAINEL DE ADMINISTRAÇÃO (Para você aprovar os acessos)
# -------------------------------------------------------------
PAINEL_HTML = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Painel de Aprovação - verAddr</title>
    <style>
        body { font-family: sans-serif; background: #121212; color: #fff; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #222; }
        .btn { padding: 6px 12px; border-radius: 4px; text-decoration: none; color: #fff; font-weight: bold; }
        .btn-aprovar { background: #28a745; }
        .btn-revogar { background: #dc3545; }
    </style>
</head>
<body>
    <h1>Painel de Controle de Acesso</h1>
    
    <h2>Acessos Pendentes (Aguardando sua Aprovação)</h2>
    <table>
        <tr>
            <th>User-Agent (Identificador)</th>
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
        <tr><td colspan="3">Nenhum acesso pendente no momento.</td></tr>
        {% endfor %}
    </table>

    <h2>Acessos Aprovados (JSON Liberado)</h2>
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
</body>
</html>
"""

@app.route('/admin')
def painel_admin():
    return render_template_string(PAINEL_HTML, pendentes=DISPOSITIVOS_PENDENTES, aprovados=DISPOSITIVOS_APROVADOS)

@app.route('/admin/aprovar')
def aprovar():
    dispositivo_id = request.args.get('id')
    if dispositivo_id:
        DISPOSITIVOS_APROVADOS.add(dispositivo_id)
        DISPOSITIVOS_PENDENTES.pop(dispositivo_id, None)
    return '<script>window.location.href="/admin";</script>'

@app.route('/admin/revogar')
def revogar():
    dispositivo_id = request.args.get('id')
    if dispositivo_id and dispositivo_id in DISPOSITIVOS_APROVADOS:
        DISPOSITIVOS_APROVADOS.remove(dispositivo_id)
    return '<script>window.location.href="/admin";</script>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
