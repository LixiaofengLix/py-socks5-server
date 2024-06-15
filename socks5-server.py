import socket
import struct
import select
import threading

LOCAL_IP = '0.0.0.0'

# 定义 SOCKS5 协议相关常量
SOCKS_VERSION = b'\x05'
METHOD_NO_AUTH = b'\x00'
METHOD_NOT_ACCEPTABLE = b'\xFF'
CMD_CONNECT = 1
CMD_UDP_ASSOCIATE = 3
ADDR_TYPE_IPV4 = 1
ADDR_TYPE_DOMAIN = 3
ADDR_TYPE_IPV6 = 4
REPLY_SUCCEEDED = b'\x00'
REPLY_GENERAL_FAILURE = b'\x01'
REPLY_COMMAND_NOT_SUPPORTED = b'\x07'
REPLY_ADDR_TYPE_NOT_SUPPORTED = b'\x08'

def handle_tcp_proxy(sock, dst_addr, dst_port):
    try:
        # TCP Step2: 连接到目标服务器，建立 TCP 链接
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((dst_addr, dst_port))
        local_addr, local_port = tcp_sock.getsockname()
        print(f'[Server TCP Step2] connect {dst_addr}:{dst_port}')

        # TCP Step3: 告诉客户端链接已建立
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        response = b'\x05\x00\x00\x01' + socket.inet_aton(local_addr) + struct.pack('>H', local_port)
        sock.sendall(response)
        print(f'[Server TCP Step3] local_addr={local_addr}, local_port={local_port}')

        # TCP Step4 / TCP Step5 / TCP Step6: 转发 TCP 请求
        while True:
            r, w, e = select.select([sock, tcp_sock], [], [])
            if sock in r:
                data = sock.recv(4096)
                if not data:
                    break
                tcp_sock.sendall(data)
            if tcp_sock in r:
                data = tcp_sock.recv(4096)
                if not data:
                    break
                sock.sendall(data)
    finally:
        tcp_sock.close()

def handle_udp_proxy(sock, dst_addr, dst_port):
    try:
        # UDP Step2: 建立 UDP 端口
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind((LOCAL_IP, 0))
        _, local_port = udp_sock.getsockname()
        print(f'[Server UDP Step2] connect {LOCAL_IP}:{local_port}')

        # UDP Step3: 告诉客户端 UDP 端口已建立
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        response = b'\x05\x00\x00\x01' + socket.inet_aton(LOCAL_IP) + struct.pack('>H', local_port)
        sock.sendall(response)

        # UDP Step4 / UDP Step5: 转发 UDP 请求
        while True:
            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +----+------+------+----------+----------+----------+
            # | 2  |  1   |  1   | Variable |    2     | Variable |
            # +----+------+------+----------+----------+----------+
            data, addr = udp_sock.recvfrom(4096)
            # 默认不分包
            if data[0] != 0 or data[1] != 0 or data[2] != 0:
                continue  # Invalid UDP request

            addr_type = data[3]
            if addr_type == ADDR_TYPE_IPV4:  # IPv4
                target_addr = socket.inet_ntoa(data[4:8])
                target_port = struct.unpack('>H', data[8:10])[0]
                payload = data[10:]
            elif addr_type == ADDR_TYPE_DOMAIN:  # Domain name
                domain_len = data[4]
                target_addr = data[5:5 + domain_len]
                target_port = struct.unpack('>H', data[5 + domain_len:7 + domain_len])[0]
                payload = data[7 + domain_len:]
            else:
                continue  # Unsupported address type

            udp_sock.sendto(payload, (target_addr, target_port))

            response, _ = udp_sock.recvfrom(4096)

            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +----+------+------+----------+----------+----------+
            # | 2  |  1   |  1   | Variable |    2     | Variable |
            # +----+------+------+----------+----------+----------+
            udp_sock.sendto(b'\x00\x00\x00\x01' + socket.inet_aton(target_addr) + struct.pack('>H', target_port) + response, addr)
    finally:
        udp_sock.close()

def handle_tcp(sock):

    try:
        # 协商 Step1: 验证 socks 版本以及协议验证方式
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        # | 1  |    1     | 1 to 255 |
        # +----+----------+----------+
        ver = sock.recv(1)
        if ver != SOCKS_VERSION:
            raise Exception(f'Unsupported Socks Version: {ver}')
        nmethods = sock.recv(1)[0]
        methods = sock.recv(nmethods)
        print(f'[Client 协商 Step1] VER={ver}, NMETHODS={nmethods}, METHODS={methods}')

        # 协商 Step2: 服务器选择其中一种验证方式
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        # | 1  |   1    |
        # +----+--------+
        sock.sendall(SOCKS_VERSION+METHOD_NO_AUTH)  # 这里默认选择不验证(0x00), 其他验证方式需要额外实现
        print(f'[Server 协商 Step2]: VER=5, METHOD=0')

        # TCP Step1 / UDP Step1: 客户端请求连接
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        ver, cmd, rsv, atyp = sock.recv(4)
        if cmd not in (CMD_CONNECT, CMD_UDP_ASSOCIATE):   # 仅支持 tcp 和 udp
            raise Exception(f'[Client TCP Step1 / UDP Step1] Unsupported Request Types: {cmd}')
        
        if atyp == ADDR_TYPE_IPV4:  # IPv4
            dst_addr = socket.inet_ntoa(sock.recv(4))
        elif atyp == ADDR_TYPE_IPV6:  # Domain name
            domain_len = sock.recv(1)[0]
            dst_addr = sock.recv(domain_len)
        else:
            raise Exception(f'[Client TCP Step1 / UDP Step1] Unsupported IP Protocol: {atyp}')
        dst_port = struct.unpack('>H', sock.recv(2))[0]
        print(f'[Client TCP Step1 / UDP Step1]: VER={ver}, CMD={cmd}, RSV={rsv}, ATYP={atyp}, DST.ADDR={dst_addr}, DST.PORT={dst_port}')

        if cmd == CMD_CONNECT:
            handle_tcp_proxy(sock, dst_addr, dst_port)
        if cmd == CMD_UDP_ASSOCIATE:
            handle_udp_proxy(sock, dst_addr, dst_port)
    except Exception as ex:
        print(ex)
    finally:
        sock.close()

def main():
    global LOCAL_IP
    tsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tsock.connect(("8.8.8.8", 80))
    LOCAL_IP = tsock.getsockname()[0]
    tsock.close()

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind(('0.0.0.0', 1080))
    tcp_sock.listen(5)

    while True:
        client_sock, _ = tcp_sock.accept()
        client_handler = threading.Thread(target=handle_tcp, args=(client_sock,))
        client_handler.start()

if __name__ == '__main__':
    main()
