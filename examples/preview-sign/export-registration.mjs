/**
 * Package a browser-created PreviewSign registration for RP storage/export
 * and direct C_CreateObject import through
 * CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION. The RP must validate the ceremony.
 */
export function exportPreviewSignRegistration(credential, rpId) {
  const generated = credential.getClientExtensionResults().previewSign?.generatedKey;
  if (!generated || credential.type !== "public-key" || !rpId) {
    throw new Error("A PreviewSign registration and its actual RP ID are required");
  }
  const base64url = (buffer) => {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const id = base64url(credential.rawId);
  return {
    schema: "pkcs11rs.preview-sign.webauthn",
    version: 1,
    rpId,
    credential: {
      id,
      rawId: id,
      type: "public-key",
      response: {
        clientDataJSON: base64url(credential.response.clientDataJSON),
        attestationObject: base64url(credential.response.attestationObject),
      },
      clientExtensionResults: {
        previewSign: {
          generatedKey: {
            keyHandle: base64url(generated.keyHandle),
            publicKey: base64url(generated.publicKey),
            algorithm: generated.algorithm,
            attestationObject: base64url(generated.attestationObject),
          },
        },
      },
    },
  };
}
