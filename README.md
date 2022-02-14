# Text messenger

The aim of the project was to develop a client-server text messenger service using SCTP and UDP multicast protocols. The project is distinguished by the lack of server use -
we have created one application that handles the entire communication process.

We wanted the application to be as universal as possible, so we divided the process into a parent and child process, which allowed for simultaneous receiving and sending of messages. The SCTP protocol supports private chat in the project, we set up a one-to-many connection in order to skip establishing a connection in the client-server style. After selecting the private chat option, we must provide the IPv4 address of the user with whom we want to chat. UDP multicast supports group chat with more users, the address to which we connect and the interface are pre-set. The creation of the receiving and sending socket is performed using the appropriate functions: snd / rcv_udp_socket or snd / rcv_sctp_socket. Sending and receiving messages is performed by the following functions: send / recv_all or send_priv / recv_priv

The program uses the "enp0s8" network interface that supports
communication between two virtual machines, starting communication between two computers would require changing this interface.

# Usage

Compiling
```
make
```
Running aplication
```
./chat <nickname>
```

We choose the option by entering the corresponding number into the console. Each option can be exited by typing "exit".

# Screenshots

Main menu:

![image](https://user-images.githubusercontent.com/56135959/153872495-3f8e4ce2-c1d5-42cb-a722-bbb093801ab3.png)

Private chat:

![image](https://user-images.githubusercontent.com/56135959/153872514-96f26038-e363-4cfb-8925-f1806706f675.png)

Group chat:

![image](https://user-images.githubusercontent.com/56135959/153872534-142bb899-dc78-4d9b-a2d8-a87c48f22d73.png)

Exiting the application:

![image](https://user-images.githubusercontent.com/56135959/153872547-cdc3a8fe-4e1d-4a84-ad14-fd3f8f554280.png)

# Authors

[Michał Kaszuba](https://github.com/kaszubam9)

[Michał Ptak](https://github.com/mptak12)
