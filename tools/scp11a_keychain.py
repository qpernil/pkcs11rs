"""External developer provisioning for an existing iOS smoke-app host key.

Import into LLDB after attaching to the app, stopped after its libraries load:
  command script import /path/to/scp11a_keychain.py
  scp11a-export iphone-qpernil /tmp/host-public.sec1
  scp11a-install iphone-qpernil /tmp/host.der

Only the public key/certificate is transferred. No app provisioning code or
system trust-root installation is required. Requires a debuggable, unlocked app.
"""
import base64
import json
import shlex
from pathlib import Path

import lldb


def evaluate(debugger, source):
    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC_plus_plus)
    options.SetIgnoreBreakpoints(True)
    options.SetTimeoutInMicroSeconds(30_000_000)
    value = debugger.GetSelectedTarget().EvaluateExpression(source, options)
    if value.GetError().Fail():
        raise RuntimeError(value.GetError().GetCString())
    return value


def host_point(debugger, name):
    evaluate(debugger, "@import Foundation")
    evaluate(debugger, "@import Security")
    name_literal = json.dumps(name, ensure_ascii=True)
    source = f"""({{
        unsigned char point[65]; unsigned long length = sizeof(point);
        unsigned long rv = (unsigned long)PKCS11RS_PlatformCredentialGetPublicKey(
            (const unsigned char *){name_literal}, {len(name.encode())}, point, &length);
        rv == 0 && length == 65
            ? [[NSData dataWithBytes:point length:length] base64EncodedStringWithOptions:0]
            : (NSString *)nil;
    }})"""
    summary = evaluate(debugger, source).GetSummary()
    if not summary:
        raise RuntimeError("Existing host public key is unavailable; no key was created")
    return base64.b64decode(json.loads(summary.removeprefix("@")), validate=True)


def export(debugger, command, result, internal_dict):
    try:
        name, destination = shlex.split(command)
        point = host_point(debugger, name)
        with Path(destination).open("xb") as output:
            output.write(point)
        result.AppendMessage(f"Exported existing host public key ({len(point)} bytes)")
    except Exception as error:
        result.SetError(str(error))


def install(debugger, command, result, internal_dict):
    try:
        name, certificate_path = shlex.split(command)
        point = base64.b64encode(host_point(debugger, name)).decode()
        certificate = base64.b64encode(Path(certificate_path).read_bytes()).decode()
        label = json.dumps(f"pkcs11rs SCP11a OCE {name}", ensure_ascii=True)
        source = f"""({{
            NSData *der = [[NSData alloc] initWithBase64EncodedString:@"{certificate}" options:0];
            NSData *expected = [[NSData alloc] initWithBase64EncodedString:@"{point}" options:0];
            SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)der);
            SecKeyRef key = cert ? SecCertificateCopyKey(cert) : NULL;
            CFDataRef actual = key ? SecKeyCopyExternalRepresentation(key, NULL) : NULL;
            int status = actual && [(NSData *)actual isEqualToData:expected]
                ? (int)SecItemAdd((CFDictionaryRef)@{{
                    (id)kSecClass:(id)kSecClassCertificate,
                    (id)kSecValueRef:(id)cert, (id)kSecAttrLabel:@{label}
                }}, NULL) : -50;
            if (status == -25299) {{
                CFTypeRef existing = NULL;
                status = (int)SecItemCopyMatching((CFDictionaryRef)@{{
                    (id)kSecClass:(id)kSecClassCertificate,
                    (id)kSecAttrLabel:@{label}, (id)kSecReturnData:@YES
                }}, &existing);
                if (status == 0 && ![(NSData *)existing isEqualToData:der]) status = -50;
                if (existing) CFRelease(existing);
            }}
            if (actual) CFRelease(actual);
            if (key) CFRelease(key);
            if (cert) CFRelease(cert);
            status;
        }})"""
        status = evaluate(debugger, source).GetValueAsSigned()
        if status != 0:
            raise RuntimeError(f"Certificate installation failed: OSStatus {status}")
        result.AppendMessage("Matching OCE certificate installed or already present in app Keychain")
    except Exception as error:
        result.SetError(str(error))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(f"command script add -f {__name__}.export scp11a-export")
    debugger.HandleCommand(f"command script add -f {__name__}.install scp11a-install")
