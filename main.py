import socket
import os
import scapy




def main():
    
    Host = input("IP:: ")
    print(Host)
    ##preciso de ver a biblioteca scapy para criar os sockets e não criar há mão
    #tipo de OS que é usado   
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    sniffer.bind((Host, 0))

    # inclide the IP header in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'int':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    print(sniffer.recvfrom(65565))
     
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__=="__main__":
    main()
