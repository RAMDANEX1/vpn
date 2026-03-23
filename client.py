import socket
from config import HOST, PORT, BUFFER_SIZE, ENCODING, SHARED_KEY
from crypto import chiffrer, dechiffrer


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print(f"Connecte au serveur {HOST}:{PORT}")
        print("Tapez 'quit' pour fermer.")

        while True:
            message = input("Vous: ").strip()
            if not message:
                continue
            if message.lower() == "quit":
                break

            payload = chiffrer(message, SHARED_KEY).encode(ENCODING)
            client_socket.sendall(payload)

            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                print("Connexion fermee par le serveur.")
                break

            reponse = dechiffrer(data.decode(ENCODING), SHARED_KEY)
            print(f"Serveur: {reponse}")


if __name__ == "__main__":
    main()
