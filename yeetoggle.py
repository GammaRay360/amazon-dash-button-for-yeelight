import miio
import socket
import struct

SYNC_PACKET = bytes.fromhex(
    "21 31 00 20 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff")
TOGGLE_PAYLOAD = bytes.fromhex(
    "7b 22 69 64 22 3a 31 2c 22 6d 65 74 68 6f 64 22 3a 22 74 6f 67 67 6c 65 22 2c 22 70 61 72 61 6d 73 22 3a 5b 5d 7d")
BROADCAST_IP = "<broadcast>"  # if this doesn't work, replace with your network's broadcast ip.
UDP_PORT = 54321
IP = 0
PORT = 1
BUFFER_SIZE = 1024


def toggle(token=None):
    """
    Find the device's ip, id, timestamp.
    Try to find the device's token. (see :param token:).
    Use those to toggle the device.
    :param token: (optional) if your device is uninitialized, you can leave this empty. the device will reveal it's
                    token. if your device already initialized you'll have to find the token yourself and put it here.
    """
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(SYNC_PACKET, (BROADCAST_IP, UDP_PORT))
    #print("Sync packet sent:")
    #miio.print_header(SYNC_PACKET)
    while True:
        data, address = sock.recvfrom(BUFFER_SIZE)  # buffer size is 1024 bytes
        break
    target_ip = address[IP]

    if (data == SYNC_PACKET and token is None):
        print("received sync packet without token. aborting.")
        return

    #print("received sync packet from ip {}:".format(target_ip))
    #miio.print_header(data)
    head = data[:32]
    magic, packet_len, unknown1, did, time_stamp, token = \
        struct.unpack('!2sHIII16s', head)

    packet_toggle = miio.encrypt(time_stamp + 10, did, token, TOGGLE_PAYLOAD)
    #print("sending packet:")
    #miio.print_header(packet_toggle)
    sock.sendto(packet_toggle, (target_ip, UDP_PORT))
    #print("packet sent")

    while True:
        data, address = sock.recvfrom(1024)  # buffer size is 1024 bytes
        break

    #print("received packet:")
    #miio.print_header(data)


if __name__ == "__main__":
    toggle()
