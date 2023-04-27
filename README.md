# p2p-infra
Projeto final da disciplina de Redes

# Introdução
O projeto apresentado é um sistema de segurança em uma arquitetura Peer-to-Peer (P2P) que utiliza criptografia assimétrica e simétrica para proteger a confidencialidade e autenticidade das mensagens trocadas entre os usuários. A implementação emprega algoritmos de criptografia e hash amplamente reconhecidos e seguros: ‘Advanced Encryption Standard (AES)’ com chave de 256 bits, ‘RSA’ com chave de 4096 bits e o ‘hash Secure Hash Algorithm 256 (SHA256)’.

# Como rodar
- Verifique se você possui o Python 3.8.10 instalado em seu sistema. Caso contrário, instale o Python 3.8.10 a partir do site oficial (https://www.python.org/downloads/)
- Instale a biblioteca pycryptodome:
     Para usuários que não possuem o sistema operacional Linux: pip3 install pycryptodome
     Para usuários do sistema operacional Linux que enfrentam problemas com a versão mais recente da biblioteca, instale a versão 3.5: pip3 install pycryptodome==3.5
- Clone o o nosso repositório (https://github.com/mldmcin/seguranca-p2p.git)
- Abra o terminal ou prompt de comando e navegue até o diretório onde você salvou o arquivo projeto.py
Execute o script usando o comando: python3 projeto.py

# Dependencies
python 3.8.10<br>
pycryptodome 3.5

`pip3 install pycryptodome==3.5`


# OBS!!

O script do arquivo p2p_socket_v1.py não está terminado e nem rodando como deveria
