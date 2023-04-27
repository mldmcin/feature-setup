import time
import socket
import threading
import pickle
from contextlib import closing
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


HOST = '127.0.0.1'
PORT = 65432
stop_server = False

# criar o servidor TCP
def criar_servidor_tcp(host, port, handle_client):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    def accept_connections():
        global stop_server
        while not stop_server:
            client_socket, client_addr = server_socket.accept()
            print(f"Conexão recebida de {client_addr}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_addr, chaves_rsa, chaves_aes), name="handle_client")
            client_thread.start()

    accept_thread = threading.Thread(target=accept_connections)
    accept_thread.start()

    return server_socket, accept_thread


# criar o cliente TCP
def criar_cliente_tcp(host, port, data, remetente, destinatario):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        client_socket.sendall(data)
        client_socket.sendall(f"{remetente},{destinatario}".encode('utf-8'))

# gerar as chaves RSA e as chaves AES
def gerar_chaves():
    chaves_rsa = []
    chaves_aes = []
    for _ in range(3):
        chave_rsa = RSA.generate(4096)
        chaves_rsa.append(chave_rsa)
        chave_aes = get_random_bytes(32)
        chaves_aes.append(chave_aes)
    return chaves_rsa, chaves_aes

# criptografar a mensagem com AES e RSA
def criptografar_mensagem(mensagem, chave_rsa_remetente, chave_rsa_destinatario, chave_aes_remetente):
    start_time = time.time()

    # criptografar a mensagem com AES
    cipher_aes = AES.new(chave_aes_remetente, AES.MODE_CBC)
    cipher_text = cipher_aes.encrypt(pad(mensagem.encode('utf-8'), AES.block_size))

    # criptografar a chave AES com a chave pública do receptor
    cifra_rsa = PKCS1_OAEP.new(chave_rsa_destinatario.publickey())
    chave_aes_criptografada = cifra_rsa.encrypt(chave_aes_remetente)
    hash_mensagem = SHA256.new(mensagem.encode())
    # assinar a mensagem com a chave privada do remetente
    assinatura = pkcs1_15.new(chave_rsa_remetente).sign(hash_mensagem)

    end_time = time.time()
    tempo_criptografia = end_time - start_time
    return (cipher_aes.iv, chave_aes_criptografada, assinatura, cipher_text), tempo_criptografia

# descriptografar a mensagem com AES e RSA
def descriptografar_mensagem(vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado,
                             chave_rsa_remetente, chave_rsa_destinatario):
    start_time = time.time()

    # descriptografar a chave AES com a chave privada do receptor
    cipher_rsa = PKCS1_OAEP.new(chave_rsa_destinatario)
    chave_aes = cipher_rsa.decrypt(chave_aes_criptografada)

    # descriptografar o texto cifrado usando a chave AES e o vetor de inicialização
    cipher_aes = AES.new(chave_aes, AES.MODE_CBC, vetor_inicializacao)
    mensagem_descriptografada = unpad(cipher_aes.decrypt(texto_cifrado), AES.block_size).decode('utf-8')

    # calcular o tempo de descriptografia
    end_time = time.time()
    tempo_descriptografia = end_time - start_time

    # verificar a assinatura usando a chave pública do remetente
    hash_mensagem = SHA256.new(mensagem_descriptografada.encode())
    try:
        pkcs1_15.new(chave_rsa_remetente.publickey()).verify(hash_mensagem, assinatura)
    except (ValueError, TypeError):
        raise ValueError("A assinatura é inválida!")

    # retorna a mensagem descriptografada e o tempo de descriptografia
    return mensagem_descriptografada, tempo_descriptografia


def iniciar_servidor_tcp(host, port, chaves_rsa, chaves_aes):

    def handle_client(client_socket, addr, chaves_rsa, chaves_aes):
        data = client_socket.recv(4096)
        split_data = data.split(b'---')
        vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado = split_data[:4]
        remetente, destinatario = int.from_bytes(split_data[4], 'big'), int.from_bytes(split_data[5], 'big')

        mensagem_descriptografada, _ = descriptografar_mensagem(*split_data, chaves_rsa[remetente],
                                                                chaves_rsa[destinatario])
        print(f"Usuário {destinatario + 1} recebeu: {mensagem_descriptografada}")

        client_socket.close()

    server_socket = criar_servidor_tcp(host, port, handle_client)
    server_socket, accept_thread = server_socket

    try:
        while not stop_server:
            client_socket, client_addr = server_socket.accept()
            client_thread = threading.Thread(target=criar_cliente_tcp,
                                             args=(HOST, PORT, split_data, remetente, destinatario_1))
            client_thread.start()
    finally:
        server_socket.close()


def parar_servidor_tcp():
    global stop_server
    stop_server = True


# simular a comunicação P2P e calcular as métricas de desempenho
def simular_comunicacao_p2p(mensagens, chaves_rsa, chaves_aes):
    HOST = '127.0.0.1'
    PORT = 12345

    # Iniciar o servidor TCP em uma thread separada
    server_thread = threading.Thread(target=iniciar_servidor_tcp, args=(HOST, PORT, chaves_rsa, chaves_aes))
    server_thread.start()

    # Aguardar um pouco para garantir que o servidor esteja pronto para aceitar conexões
    time.sleep(1)

    tempo_total_criptografia = 0
    tempo_total_descriptografia = 0
    tempo_total_transmissao = 0
    tamanho_total_pacote = 0

    for i in range(len(mensagens)):
        print(f"Enviando mensagem {i + 1}: {mensagens[i]}")
        remetente = i % 3
        destinatario_1 = (i + 1) % 3
        destinatario_2 = (i + 2) % 3

        # Criptografar a mensagem e enviar para o primeiro destinatário
        (vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado), tempo_criptografia = criptografar_mensagem(
            mensagens[i], chaves_rsa[remetente], chaves_rsa[destinatario_1], chaves_aes[remetente])
        data = b'---'.join(
            [vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado, remetente.to_bytes(1, 'big'),
             destinatario_1.to_bytes(1, 'big')])

        criar_cliente_tcp(HOST, PORT, data, remetente, destinatario_1)

        tempo_total_criptografia += tempo_criptografia
        tamanho_total_pacote += len(vetor_inicializacao) + len(chave_aes_criptografada) + len(assinatura) + len(texto_cifrado)

        # Criptografar a mensagem e enviar para o segundo destinatário
        (vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado), tempo_criptografia = criptografar_mensagem(
            mensagens[i], chaves_rsa[remetente], chaves_rsa[destinatario_2], chaves_aes[remetente])
        data = b'---'.join(
            [vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado, remetente.to_bytes(1, 'big'),
             destinatario_2.to_bytes(1, 'big')])

        criar_cliente_tcp(HOST, PORT, data, remetente, destinatario_2)

        tempo_total_criptografia += tempo_criptografia
        tamanho_total_pacote += len(vetor_inicializacao) + len(chave_aes_criptografada) + len(assinatura) + len(texto_cifrado)

        # Simular o tempo de transmissão (exemplo: 0.05 segundos)
        time.sleep(0.05)
        tempo_total_transmissao += 0.05 * 2

    # Aguardar um pouco para garantir que todas as mensagens sejam processadas
    time.sleep(1)

    print("\nMétricas de desempenho:")
    print(f"Tempo total de criptografia: {tempo_total_criptografia:.2f} segundos")
    print(f"Tempo total de descriptografia: {tempo_total_descriptografia:.2f} segundos")
    print(f"Tempo total de transmissão: {tempo_total_transmissao:.2f} segundos")
    print(f"Tempo total gasto: {tempo_total_criptografia + tempo_total_descriptografia + tempo_total_transmissao:.2f} segundos")
    print(f"Tamanho total do pacote: {tamanho_total_pacote} bytes")

    # Parar o servidor TCP e encerrar a thread
    parar_servidor_tcp()
    server_thread.join()



# executar a simulação
if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 12345

    stop_server = False

    print("Servidor iniciado em", HOST, "na porta", PORT)

    mensagens = [
        "Obra na BR-101",
        "Obra na PE-015",
        "Acidente Avenida Norte",
        "Acidente Avenida Cruz Cabugá",
        "Trânsito Intenso na Avenida Boa viagem",
        "Trânsito Intenso na Governador Agamenon Magalhães"
    ]


    chaves_rsa, chaves_aes = gerar_chaves()

    simular_comunicacao_p2p(mensagens, chaves_rsa, chaves_aes)

    stop_server = True
    accept_connections_thread.join()
