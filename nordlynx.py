import frida
from time import sleep
import psutil
import pathlib
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

def print_border(msg, indent=1, width=None, title=None):
    lines = msg.split('\n')
    space = " " * indent
    if not width:
        width = max(map(len, lines))
    box = f'╔{"═" * (width + indent * 2)}╗\n'
    if title:
        box += f'║{space}{title:<{width}}{space}║\n'
        box += f'║{space}{"-" * len(title):<{width}}{space}║\n'
    box += ''.join([f'║{space}{line:<{width}}{space}║\n' for line in lines])
    box += f'╚{"═" * (width + indent * 2)}╝'
    print(box)

def onMessage(message, data):
    if 'PrivateKey' not in message["payload"]: return
    sp = message["payload"].split('\r\n')
    privateKey = sp[1].replace('PrivateKey = ', '')
    privateKey = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(privateKey))
    publicKey = base64.b64encode(privateKey.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    sp.insert(2, 'PublicKey = ' + publicKey.decode('UTF-8'))
    result = ('\n'.join(sp))[:-1]
    with open(str(pathlib.Path(__file__).parent.resolve())+"\profile.conf", "w") as file:
        file.write(result)
    print_border(result)

find = False
print("""
███╗   ██╗ ██████╗ ██████╗ ██████╗ ██╗     ██╗   ██╗███╗   ██╗██╗  ██╗
████╗  ██║██╔═══██╗██╔══██╗██╔══██╗██║     ╚██╗ ██╔╝████╗  ██║╚██╗██╔╝
██╔██╗ ██║██║   ██║██████╔╝██║  ██║██║      ╚████╔╝ ██╔██╗ ██║ ╚███╔╝ 
██║╚██╗██║██║   ██║██╔══██╗██║  ██║██║       ╚██╔╝  ██║╚██╗██║ ██╔██╗ 
██║ ╚████║╚██████╔╝██║  ██║██████╔╝███████╗   ██║   ██║ ╚████║██╔╝ ██╗
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝
            -----  NordLynx Configuration File  -----
""")

for p in psutil.process_iter():
    if "nordvpn-service.exe" == p.name():
        session = frida.attach(p.pid)
        script = session.create_script("""
            var NordLynxResolveSettings = Module.findExportByName("nordlynxWinTun.dll", 'NordLynxResolveSettings');
            Interceptor.attach(NordLynxResolveSettings, {
                onEnter: function (args) {
                    send(ptr(args[0]).readCString(-1))
                },
                onLeave: function (args) {
                }
            });
            """)
        script.on('message', onMessage)
        script.load()
        print('[+] Select a server')
        find = True
        break

if find == True:
    while True:
        sleep(0.2)
