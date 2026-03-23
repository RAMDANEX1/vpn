import socket
from config import HOST, PORT, BUFFER_SIZE, ENCODING, SHARED_KEY
from crypto import dechiffrer, chiffrer


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    print(f"[+] Client connecte: {addr}")
    with conn:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break

            try:
                message = dechiffrer(data.decode(ENCODING), SHARED_KEY)
                print(f"[{addr}] {message}")
                reponse = f"Serveur recu: {message}"
                payload = chiffrer(reponse, SHARED_KEY).encode(ENCODING)
                conn.sendall(payload)
            except Exception as exc:
                erreur = f"Erreur serveur: {exc}"
                conn.sendall(chiffrer(erreur, SHARED_KEY).encode(ENCODING))

    print(f"[-] Client deconnecte: {addr}")


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Serveur en ecoute sur {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
