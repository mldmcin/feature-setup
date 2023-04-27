import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

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
def descriptografar_mensagem(vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado, chave_rsa_remetente, chave_rsa_destinatario):
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

# simular a comunicação P2P e calcular as métricas de desempenho
def simular_comunicacao_p2p(mensagens, chaves_rsa, chaves_aes):
    tempo_total_criptografia = 0
    tempo_total_descriptografia = 0
    tempo_total_transmissao = 0
    tamanho_total_pacote = 0

    for i in range(len(mensagens)):
        print(f"Enviando mensagem {i + 1}: {mensagens[i]}")
        remetente = i % 3
        destinatario_1 = (i + 1) % 3
        destinatario_2 = (i + 2) % 3

        # criptografar a mensagem e registrar o tempo
        (vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado), tempo_criptografia = criptografar_mensagem(
            mensagens[i], chaves_rsa[remetente], chaves_rsa[destinatario_1], chaves_aes[remetente])

        tempo_total_criptografia += tempo_criptografia
        tamanho_total_pacote += len(vetor_inicializacao) + len(chave_aes_criptografada) + len(assinatura) + len(texto_cifrado)

        # simular o tempo de transmissão (exemplo: 0.05 segundos)
        tempo_transmissao = 0.05
        time.sleep(tempo_transmissao)
        tempo_total_transmissao += tempo_transmissao

        # descriptografar a mensagem e registrar o tempo
        mensagem_descriptografada1, tempo_descriptografia = descriptografar_mensagem(
            vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado, chaves_rsa[remetente], chaves_rsa[destinatario_1])
        tempo_total_descriptografia += tempo_descriptografia
        print(f"Usuário {destinatario_1 + 1} recebeu: {mensagem_descriptografada1}")

        # repetir o processo para o segundo receptor
        (vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado), tempo_criptografia = criptografar_mensagem(
            mensagens[i], chaves_rsa[remetente], chaves_rsa[destinatario_2], chaves_aes[remetente])
        tempo_total_criptografia += tempo_criptografia
        tamanho_total_pacote += len(vetor_inicializacao) + len(chave_aes_criptografada) + len(assinatura) + len(texto_cifrado)

        tempo_transmissao = 0.05
        time.sleep(tempo_transmissao)
        tempo_total_transmissao += tempo_transmissao

        mensagem_descriptografada2, tempo_descriptografia = descriptografar_mensagem(
            vetor_inicializacao, chave_aes_criptografada, assinatura, texto_cifrado, chaves_rsa[remetente], chaves_rsa[destinatario_2])
        tempo_total_descriptografia += tempo_descriptografia
        print(f"Usuário {destinatario_2 + 1} recebeu: {mensagem_descriptografada2}")

    print("\nMétricas de desempenho:")
    print(f"Tempo total de criptografia: {tempo_total_criptografia:.2f} segundos")
    print(f"Tempo total de descriptografia: {tempo_total_descriptografia:.2f} segundos")
    print(f"Tempo total de transmissão: {tempo_total_transmissao:.2f} segundos")
    print(f"Tempo total gasto: {tempo_total_criptografia + tempo_total_descriptografia + tempo_total_transmissao:.2f} segundos")
    print(f"Tamanho total do pacote: {tamanho_total_pacote} bytes")


# executar a simulação
if __name__ == "__main__":
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
    