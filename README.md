# Projeto Sniffer + Página de Login (Captura HTTP)

## 📌 Projeto

Este projeto é dividido em duas partes principais:

- **Sniffer (capturador de pacotes)**: Desenvolvido em Python, é responsável por capturar pacotes das camadas TCP, UDP e HTTP. Ele exibe informações como IPs de origem/destino, portas, timestamp e o conteúdo (payload) da comunicação.
- **Página de Login (web)**: Um formulário simples em HTML que simula o envio de um nome de usuário e senha via método POST, gerando tráfego HTTP para ser capturado pelo sniffer.

---

## ✅ Requisitos

- **Sistema Operacional**:
  - Linux (recomendado, executar como root)
  - Windows (testado com permissão de administrador)
- **Python**: Versão 3.8 ou superior
- **Permissões**: Necessário executar com permissões de administrador/root
- **Dependências**:
  ```bash
  pip install psutil


## Estrutura
.
├── app.js           (Backend simulado para receber POST)
├── index.html       (Página de login)
├── README.md        (Este guia)
└── sniffer.py       (Programa de captura de pacotes)

## Executar:

cd sniffer

sudo python3 sniffer.py (Ou somente pyton sniffer.py)

## Tela:

A interface do sniffer é simples:

No canto superior esquerdo, você verá o campo "interface:"

Selecione a interface desejada, como: Ethernet, Ethernet 2, Wi-Fi, ou Loopback

Clique em "Iniciar Captura" para começar

Para parar, clique em "Parar Captura"

No programa, aparecerá algo tipo:

[12:34:56] TCP | 192.168.0.10:54213 -> 192.168.0.1:80 | Payload: POST /login HTTP/1.1...

## Teste na pagina de login

Abra o arquivo web/index.html no navegador (basta clicar duas vezes ou usar file:///...).

Preencha com qualquer usuário/senha e clique em "Entrar".

O navegador enviará um POST para http://localhost:3000/login (ou endereço similar), gerando tráfego para o sniffer capturar.
