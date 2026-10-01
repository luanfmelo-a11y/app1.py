import os
from flask import Flask, jsonify, request

app = Flask(__name__)

# Aplicar CORS para garantir que nenhuma requisição seja bloqueada no navegador ou jogo
@app.after_request
def aplicar_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    return response

# -------------------------------------------------------------
# ROTA PÚBLICA (LIBERADA PARA TODOS)
# -------------------------------------------------------------
@app.route("/verAddr", methods=["GET", "POST", "OPTIONS"])
def gateway_ver_addr():
    if request.method == "OPTIONS":
        return "", 200

    # Retorna o JSON liberado diretamente sem verificação
    return jsonify({
        "status": "sucesso",
        "verAddr": "http://2.25.132.119:2223/aalto/false/false/false/false/false/false/false/false/"
    }), 200

# Rota de teste geral para qualquer outro caminho
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "OPTIONS"])
def catch_all(path):
    if request.method == "OPTIONS":
        return "", 200
    return jsonify({
        "status": "sucesso",
        "mensagem": "Servidor online e sem bloqueios."
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
