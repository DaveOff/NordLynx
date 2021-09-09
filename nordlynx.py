import frida
from time import sleep
import psutil
import pathlib
import base64
import argparse
import json, requests, sys, os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

find = False

argParser = argparse.ArgumentParser()
argParser.add_argument('-a', action='store_true')
args = argParser.parse_args()

def progress(count, total, suffix=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s%s\r' % (bar, percents, '%', suffix))
    sys.stdout.flush()

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
    address = sp[2].replace('Address = ', '')
    allowedIPs = sp[7].replace('AllowedIPs = ', '')
    dns = sp[3].replace('DNS = ', '')
    keepAlive = sp[9].replace('PersistentKeepalive = ', '')
    privateKey = sp[1].replace('PrivateKey = ', '')
    privateKey_X25519 = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(privateKey))
    publicKey = base64.b64encode(privateKey_X25519.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).decode('UTF-8')
    if args.a is True:
        result = request(cache=True)
        count = 0
        total = len(result)
        if result is False: return
        for k in result:
            publicKey_server = list(filter(lambda x: x["name"] == "Wireguard", k["technologies"]))
            if not publicKey_server:
                total -= 1
                continue
            publicKey_server = publicKey_server[0]["metadata"][0]["value"]
            hostName_server = k["hostname"]
            endPoint_server = k["station"]
            fileName_server = k["name"]
            output = f'[Interface]\nPrivateKey = {privateKey}\nPublicKey = {publicKey}\nAddress = {address}\nDNS = {dns}\n\n'
            output += f'[Peer]\nPublicKey = {publicKey_server}\nAllowedIPs = {allowedIPs}\nEndpoint = {endPoint_server}:51820\nPersistentKeepalive = {keepAlive}' 
            with open(str(pathlib.Path(__file__).parent.resolve())+f"\profile\{fileName_server}.conf", "w") as file:
                file.write(output)
            count += 1
            progress(count, total)
        os._exit(1)
    else:
        sp.insert(2, 'PublicKey = ' + publicKey)
        result = ('\n'.join(sp))[:-1]
        with open(str(pathlib.Path(__file__).parent.resolve())+"\profile\profile.conf", "w") as file:
            file.write(result)
        print_border(result)

def request(cache=False):
    if cache is True:
        servers = open("servers.txt", "r").read()
        return json.loads(servers)
    else:
        response = requests.get("https://zwyr157wwiu6eior.com/v1/servers?limit=2147483647&filters\[technologies\]\[identifier\]=wireguard_udp")
    if response.ok is False :
        return False
    return json.loads(response.content)

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
