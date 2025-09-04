from flask import Flask, jsonify, request
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random

app = Flask(__name__)

# Funções auxiliares
def carregar_usuarios(arch):
    try:
        url = f"https://scvirtual.alphi.media/botsistem/sendlike/{arch}"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()  # Retorna os dados dos usuários
    except requests.RequestException as e:
        print(f"Erro ao carregar usuários: {e}")
        return None


def autenticar(usuario):
    uid = usuario.get('uid')
    password = usuario.get('password')
    if not uid or not password:
        return None

    url = f"https://jwt-maker-danger.vercel.app/token?uid={uid}&password={password}"

    for attempt in range(1, 4):  # Tenta até 3 vezes
        try:
            response = requests.get(url, timeout=5)  # timeout menor para resposta mais rápida
            if response.status_code == 200:
                token = response.json().get('token')
                if token:
                    return {"uid": uid, "token": token}
                else:
                    print(f"[{uid}] Tentativa {attempt}/3 - Nenhum token recebido.")
            else:
                print(f"[{uid}] Tentativa {attempt}/3 - Status inválido: {response.status_code}")
        except requests.RequestException as e:
            print(f"[{uid}] Tentativa {attempt}/3 - Erro ao autenticar: {e}")
        
        time.sleep(0.2)  # Espera mínima para não sobrecarregar

    print(f"[{uid}] ❌ Falha após 3 tentativas de autenticação.")
    return None


def enviar_token_php(token, uid):
    """ Envia o token para um endpoint PHP """
    url = "https://scvirtual.alphi.media/botsistem/sendlike/receber_token.php"
    payload = {"uid": uid, "token": token}
    try:
        response = requests.post(url, data=payload, timeout=5)
        if response.status_code == 200:
            print(f"[{uid}] ✅ Token enviado com sucesso ao PHP.")
        else:
            print(f"[{uid}] ⚠️ Erro ao enviar token para PHP. Status {response.status_code}")
    except Exception as e:
        print(f"[{uid}] ❌ Falha ao enviar token para PHP: {e}")


def atualizar_tokens(arch):
    usuarios = carregar_usuarios(arch)
    if not usuarios:
        return None
    usuarios = remover_duplicados_e_notificar(usuarios, arch)
    novos_tokens = []
    uids_processados = set()
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for usuario in usuarios:
            uid = usuario.get('uid')
            if uid and uid not in uids_processados:
                uids_processados.add(uid)
                futures.append(executor.submit(autenticar, usuario))
        
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                token = resultado['token']
                novos_tokens.append({"token": token})
                print(f"Token recebido para {resultado['uid']}")

                # 👉 Se for acc.json, envia o token ao PHP
                if arch == "acc.json":
                    enviar_token_php(token, resultado['uid'])

    if novos_tokens:
        # Embaralha os tokens antes de retornar
        random.shuffle(novos_tokens)
        print(f"Total de tokens gerados: {len(novos_tokens)}")
        return novos_tokens
    return None


def remover_duplicados_e_notificar(usuarios, arch):
    vistos = set()
    unicos = []
    for user in usuarios:
        uid = user.get("uid")
        password = user.get("password")
        chave = (uid, password)
        if chave in vistos:
            reportar_duplicata(uid, password, arch)
        else:
            vistos.add(chave)
            unicos.append(user)
    return unicos

def reportar_duplicata(uid, password, arch):
    try:
        url = "https://scvirtual.alphi.media/botsistem/sendlike/delete_duplicate.php"
        payload = {
            "uid": uid,
            "password": password,
            "arch": arch
        }
        response = requests.post(url, data=payload, timeout=5)
        if response.status_code == 200:
            print(f"[{uid}] 🔴 Duplicata reportada e solicitada remoção.")
        else:
            print(f"[{uid}] ⚠️ Falha ao reportar duplicata. Status: {response.status_code}")
    except Exception as e:
        print(f"[{uid}] Erro ao tentar notificar o PHP: {e}")


# Rotas do Flask
@app.route('/')
def index():
    return "Servidor de tokens JWT. Use /get_tokens para recarregar e obter tokens ou /tokens?get-token=true para obter tokens novos."

@app.route('/get_tokens')
def get_tokens():
    arch = request.args.get('arch')
    tokens = atualizar_tokens(arch)
    if tokens:
        return jsonify({
            "status": "success",
            "message": "Tokens gerados com sucesso",
            "tokens": tokens,
            "count": len(tokens)
        })
    else:
        return jsonify({
            "status": "error",
            "message": "Falha ao gerar tokens"
        }), 500

@app.route('/tokens')
def gerenciar_tokens():
    get_update = request.args.get('get-update', '').lower() == 'true'
    get_token = request.args.get('get-token', '').lower() == 'true'
    arch = request.args.get('arch')
    
    if get_update or get_token:
        tokens = atualizar_tokens(arch)
        if tokens:
            return jsonify({"status": "success", "tokens": tokens, "count": len(tokens)})
        else:
            return jsonify({"status": "error", "message": "Falha ao gerar tokens"}), 500
    else:
        return jsonify({"status": "error", "message": "Parâmetro inválido. Use get-update=true ou get-token=true"}), 400

if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5000, debug=True)
