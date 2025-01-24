import socket

def main():
    # Create a raw socket
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except socket.error as e:
        print(f"Socket creation failed: {e}")
        return

    # Bind to the public network interface
    host = socket.gethostbyname(socket.gethostname())
    sniffer.bind((host, 0))

    # Include IP headers in the captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Put the network interface into promiscuous mode (Windows-only)
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except AttributeError:
        print("Promiscuous mode is not supported on this platform.")

    print(f"Listening on {host}...")

    try:
        while True:
            # Receive a packet
            packet, addr = sniffer.recvfrom(65565)
            print(f"Packet received from {addr}: {packet}")
    except KeyboardInterrupt:
        print("\nStopping the sniffer.")
    finally:
        # Turn off promiscuous mode (Windows-only)
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except AttributeError:
            pass

if __name__ == "__main__":
    main()