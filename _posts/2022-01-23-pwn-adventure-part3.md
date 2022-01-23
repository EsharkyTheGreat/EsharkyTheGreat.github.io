---
title: PwnAdventure Part3 - Memory and Structs
date: 2022-01-23 16:28:00 +0530
categories: [Pwn]
tags: [pwn,game hacking,gdb,c++,reversing]
pin: true
---

## What we're going to do
---
Now that we have an overview of the game lets load the `libGameLogic` library in a disassembler. I'm using IDA for this. Since we have debug information we'll get all the classes,structs and functions in a headerfile so that we can use the offsets properly. This is very important because I tried without getting the classes and it was just tedious.

## Disassembly
---
If we open the `libGameLogic.so` file in IDA we see that IDA automatically demangles all the function names for us.

![demangled]()

Let's also look at the data segment of the library for some global variables which can be used later.

![bss]()

## Functions
---
Let's look at the Functions that could be called when we jump. We'll set a breakpoint on the function to later to see if it was called.

![jump]()

We see that there is a function which gives the server information about jumping and this action is added to a server queue.

## GDB
---
We need sudo privileges to attach to our game client. We can attach to the process using the command - 

```bash
sudo gdb -p $(pidof ./PwnAdventure3-Linux-Shipping)
```

Then run the command to set a breakpoint on `GameServerConnection::Jump(bool)` and jump in game to trigger the breakpoint.

![bp](/assets/postimg/pwnadv3/break_jump.png)

From the backtrace we are also able to see the functions called before this which lead to this being called.

## Getting Classes and Structs
---
Now to get the classes and structs which will make our life easier when exploiting to hook function and get offsets in classes and structs  
What we'll do is use the `pytpe` command to get information about classes and structs.  
We can also inspect Global Variables in memory which we can use later.

![ptype](/assets/postimg/pwnadv3/ptype.png)

## Header File
---
We can extract all the classes and structs to get all definations and build a header file through which we'll compiler our exploit. I tried to build the header myself but was'nt successful. LiveOverflow faced the same issue as me and solved the problem and made the header file for us. [here](https://raw.githubusercontent.com/LiveOverflow/PwnAdventure3/master/tools/linux/libGameLogic.h)