import telnetlib

def run_client():
    try:
        with telnetlib.Telnet("localhost", 2323) as tn:
            print(tn.read_until(b"Welcome").decode())
            while True:
                msg = input("You (Client): ")
                tn.write(msg.encode() + b"\n")
                if msg.lower() == 'exit':
                    break
                print(tn.read_until(b"\n").decode())
    except ConnectionRefusedError:
        print("Server not running!")

if __name__ == "__main__":
    run_client()