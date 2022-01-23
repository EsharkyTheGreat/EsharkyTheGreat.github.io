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
