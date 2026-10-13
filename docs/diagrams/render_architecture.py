#!/usr/bin/env python3
"""Generate architecture.svg with Python's standard library.

Run from any directory: python3 docs/diagrams/render_architecture.py
Coordinates and labels below are the editable source; no renderer is required.
"""
from html import escape
from pathlib import Path

OUT = Path(__file__).with_name('architecture.svg')
parts = []


def add(value):
    parts.append(value)


def text(x, y, value, size=20, color='#475569', weight=400):
    add(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" '
        f'font-weight="{weight}">{escape(value)}</text>')


def rect(x, y, w, h, fill='#ffffff', stroke='#dbe3ee', radius=18):
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" '
        f'fill="{fill}" stroke="{stroke}"/>')


def card(x, y, w, h, title, lines, color='#2563eb', url=None, tag=None):
    if url:
        add(f'<a href="{escape(url, quote=True)}" target="_blank">')
    rect(x, y, w, h)
    add(f'<rect x="{x+1}" y="{y+22}" width="5" height="{h-44}" rx="2" fill="{color}"/>')
    if tag:
        text(x+24, y+29, tag.upper(), 14, color, 700)
        title_y = y+59
    else:
        title_y = y+38
    text(x+24, title_y, title, 25, '#0f172a', 700)
    for i, line in enumerate(lines):
        text(x+24, title_y+32+i*28, line, 18)
    if url:
        add('</a>')


def edge(path, dashed=False):
    color = '#b45309' if dashed else '#64748b'
    dash = ' stroke-dasharray="8 7"' if dashed else ''
    marker = 'control' if dashed else 'data'
    add(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.5" '
        f'stroke-linejoin="round"{dash} marker-end="url(#{marker})"/>')


def label(x, y, value, width, centered=False):
    rect(x-width/2 if centered else x-8, y-20, width, 29, '#f5f7fb', '#f5f7fb', 6)
    if centered:
        add(f'<text x="{x}" y="{y}" font-size="17" fill="#475569" '
            f'text-anchor="middle">{escape(value)}</text>')
    else:
        text(x, y, value, 17)


def repo(name):
    return f'https://github.com/qpernil/{name}'


add('''<svg xmlns="http://www.w3.org/2000/svg" width="1800" height="1210"
 viewBox="0 0 1800 1210" role="img" aria-labelledby="title description">
<title id="title">pkcs11rs and the virtual-device project architecture</title>
<desc id="description">Applications load the pkcs11rs provider. The provider
uses the same USB transports for physical and virtual YubiKeys and YubiHSMs,
optional embedded YubiKey cores, or a YubiHSM connector. The connector can
reach physical or virtual USB YubiHSMs, use experimental I2C, or host embedded
virtual YubiHSM cores inside its own process. Virtual USB workers run under
a privileged USB gadget supervisor; protocol traffic goes directly to workers.
Optional named software slots provide general-purpose software cryptography;
embedded virtual YubiKeys instead emulate YubiKey applets and protocol state.
Both paths use host software rather than hardware-protected private keys.
Shared software-key-core provides cryptography and durable-state helpers.
Local platform credentials can use Secure Enclave or TPM-protected keys for YubiHSM
authentication on supported platforms.
The platform key stores also support SCP11a/c host credentials.
Dashed arrows indicate supervisor lifecycle and
resource control. The accompanying architecture document lists all components.</desc>
<defs>
<marker id="data" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0 0L9 4.5L0 9" fill="#64748b"/></marker>
<marker id="control" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0 0L9 4.5L0 9" fill="#b45309"/></marker>
</defs>
<g font-family="Arial, Helvetica, sans-serif">
<rect width="1800" height="1210" rx="24" fill="#f5f7fb"/>
''')
text(60, 64, 'One provider. A connected device ecosystem.', 38, '#0f172a', 700)
text(60, 101, 'Runtime paths, project ownership, and shared infrastructure', 22)
card(60, 135, 1680, 91, 'Applications & validation clients', [
    'PKCS #11 consumers · Swift / Objective-C iOS apps · pkcs11-tester · pkcs11test · libusb-tester · Yubico Authenticator · yubihsm-shell'
], '#64748b')
text(60, 268, 'HOST PROVIDER', 15, '#2563eb', 700)
text(650, 268, 'NETWORK GATEWAY', 15, '#2563eb', 700)
text(1220, 268, 'DEVICES & USB SETUP', 15, '#0f766e', 700)

# USB device implementations share a host-facing transport boundary.
rect(1120, 285, 620, 485, '#eef2f7', '#dbe3ee')
text(1144, 325, 'USB devices — physical or virtual', 25, '#0f172a', 700)

# Data paths are drawn before cards so endpoints meet card borders cleanly.
edge('M285 226V285')
edge('M510 325H1120')
label(695, 315, 'USB: CCID / HID / YubiHSM', 270)
edge('M510 625H650')
label(526, 610, 'HTTP(S)', 98)
edge('M1070 630H1144')
label(1078, 615, 'USB', 49)
# Platform-backed YubiHSM authentication, separate from the applet client.
edge('M486 824H1220')
label(853, 851, 'Apple Security (SecKey) / Windows CNG / Linux ESAPI', 590, centered=True)
# One control spine, visually separate from protocol paths.
edge('M1740 1010H1770V475H1716', True)
edge('M1770 675H1716', True)
add('<text transform="translate(1760 965) rotate(-90)" font-size="17" '
    'fill="#475569">Virtual workers only · FDs / lifecycle</text>')

card(60, 285, 450, 585, 'pkcs11rs', [
    'PKCS #11 2.40 / 3.0 / 3.1 / 3.2 · desktop + iOS',
    'Module → slots → sessions → operations',
    'Device / software slots + OS-protected keys',
    'SCP03 / SCP11 and YubiHSM sessions',
], '#2563eb', repo('pkcs11rs'), 'Repository & Cargo workspace')
rect(84, 486, 402, 100, '#f5f3ff', '#ddd6fe', 10)
text(102, 515, 'Optional named software slots', 18, '#7c3aed', 700)
text(102, 543, 'Full software crypto; no device emulation', 18)
text(102, 570, 'Session keys + optional encrypted token store', 18)
rect(84, 604, 402, 118, '#f0fdfa', '#99f6e4', 10)
text(102, 635, 'Optional embedded virtual-yubikey-core', 18, '#0f766e', 700)
text(102, 663, 'YubiKey applets, protocols & persistent state', 18)
text(102, 691, 'In process; no USB or supervisor needed', 18)
rect(84, 740, 402, 102, '#eff6ff', '#bfdbfe', 10)
text(102, 769, 'Local workspace components', 18, '#1d4ed8', 700)
text(102, 798, 'platform-credential · yubihsm-auth-client', 18)
text(102, 824, 'pkcs11rs-local-hardware · pkcs11rs-tool', 18)

card(1220, 790, 520, 115, 'Secure Enclave / TPM 2.0', [
    'Protected keys for device authentication',
    'YubiHSM login + SCP11a/c',
], '#7c3aed', f'{repo("pkcs11rs")}/blob/master/docs/platform.md')
card(1144, 355, 572, 150, 'YubiKey / FIDO authenticators', [
    'Physical devices or virtual-yubikey USB workers',
    'CCID applets + FIDO HID',
    'Same host transport and applet discovery',
], '#0f766e', repo('virtual-yubikey'))
card(650, 540, 420, 270, 'pkcs11rs-connector', [
    'HTTP(S) / mTLS · per-device command gates',
    'USB HSMs · optional experimental I²C',
], '#2563eb', repo('pkcs11rs'), 'Network service')
rect(674, 686, 372, 100, '#f0fdfa', '#99f6e4', 10)
text(692, 715, 'Optional embedded YubiHSM', 18, '#0f766e', 700)
text(692, 744, 'virtual-yubihsm-core', 18)
text(692, 770, 'In-process device + persistent state', 18)
card(1144, 555, 572, 150, 'YubiHSM', [
    'Physical HSM or virtual-yubihsm USB worker',
    'Direct USB access or access through the connector',
    'USB worker uses the same virtual-yubihsm-core',
], '#0f766e', repo('virtual-yubihsm'))
card(1220, 950, 520, 125, 'usb-gadget-supervisor', [
    'Root: ConfigFS / FunctionFS / UDC / resources',
    'Unprivileged workers own protocol traffic',
], '#b45309', repo('usb-gadget-supervisor'))
card(60, 900, 450, 170, 'software-key-core', [
    'RSA · EC · EdDSA · AES · ML-DSA · ML-KEM',
    'X.509 & durable-state helpers',
    'Consumers: provider, platform credentials,',
    'virtual YubiKey and YubiHSM cores',
], '#7c3aed', repo('software-key-core'))

edge('M60 1152H115')
text(130, 1158, 'Protocol / API path (responses return on the same path)', 18)
edge('M700 1152H755', True)
text(770, 1158, 'Privileged setup / lifecycle control', 18)
text(60, 1190, '* I²C is opt-in and experimental. Software slots and virtual-device keys are host-held. Shared-library consumers are listed inside their cards.', 17)
add('</g></svg>\n')
OUT.write_text('\n'.join(parts), encoding='utf-8')
print(OUT)
