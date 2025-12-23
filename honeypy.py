#Libraries
import argparse
from ssh_honeypot import honeypot
from webhoneypot import run_web_honeypot

#Parse arguments

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)

    #ssh honeypot
    parser.add_argument('-s', '--ssh', action='store_true', help='Enable SSH Honeypot')

    #Web-based honeypot
    parser.add_argument('-w', '--http', action='store_true', help='Enable HTTP Honeypot')

    args = parser.parse_args()

    try:
        if args.ssh:
            print("[-] Running SSH Honeypot...")

            # Keep None if not provided (ssh_honeypot should decide behavior)
            username = args.username if args.username else None
            password = args.password if args.password else None

            honeypot(args.address, args.port, username, password)

        elif args.http:
            print("[-] Running HTTP Honeypot...")

            username = args.username if args.username else "admin"
            password = args.password if args.password else "password"

            print(f"Host {args.address}, Port {args.port}, Username: {username}, Password: {password}")

            run_web_honeypot(
                host=args.address,
                port=args.port,
                input_username=username,
                input_password=password,
            )

        else:
            print("[-] please choose a honeypot SSH or HTTP")

    except KeyboardInterrupt:
        print("\n[-] Stopped.")
    except Exception as exc:
        print(f"[-] Error: {exc}")
