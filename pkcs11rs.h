#ifndef PKCS11RS_H
#define PKCS11RS_H 1

#include "pkcs11.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PKCS11RS_SCP03_KEY_SET {
  const CK_BYTE *pEncKey;
  CK_ULONG ulEncKeyLen;
  const CK_BYTE *pMacKey;
  CK_ULONG ulMacKeyLen;
  const CK_BYTE *pDekKey;
  CK_ULONG ulDekKeyLen;
} PKCS11RS_SCP03_KEY_SET;

typedef struct PKCS11RS_BYTE_BUFFER {
  const CK_BYTE *pValue;
  CK_ULONG ulValueLen;
} PKCS11RS_BYTE_BUFFER;

#define PKCS11RS_SCP11A_KID 0x11
#define PKCS11RS_SCP11B_KID 0x13
#define PKCS11RS_SCP11C_KID 0x15

#define PKCS11RS_SCP11_CURVE_SECP256R1 0x00
#define PKCS11RS_SCP11_CURVE_SECP384R1 0x01
#define PKCS11RS_SCP11_CURVE_SECP521R1 0x02
#define PKCS11RS_SCP11_CURVE_BRAINPOOLP256R1 0x03
#define PKCS11RS_SCP11_CURVE_BRAINPOOLP384R1 0x05
#define PKCS11RS_SCP11_CURVE_BRAINPOOLP512R1 0x07

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainPutScp03KeySet)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE newKvn,
  CK_BYTE replaceKvn,
  const PKCS11RS_SCP03_KEY_SET *pKeys
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainDeleteScp03KeySet)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kvn,
  CK_BBOOL deleteLast
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainGenerateScp11Key)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kid,
  CK_BYTE newKvn,
  CK_BYTE replaceKvn,
  CK_BYTE curve,
  CK_BYTE_PTR pPublicKey,
  CK_ULONG_PTR pulPublicKeyLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainPutScp11PrivateKey)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kid,
  CK_BYTE newKvn,
  CK_BYTE replaceKvn,
  const CK_BYTE *pKey,
  CK_ULONG ulKeyLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainPutScp11PublicKey)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kid,
  CK_BYTE newKvn,
  CK_BYTE replaceKvn,
  const CK_BYTE *pKey,
  CK_ULONG ulKeyLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainStoreScp11CertificateChain)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kid,
  CK_BYTE kvn,
  const PKCS11RS_BYTE_BUFFER *pCertificates,
  CK_ULONG ulCertificateCount
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainStoreScp11CaIssuer)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kid,
  CK_BYTE kvn,
  const CK_BYTE *pSubjectKeyIdentifier,
  CK_ULONG ulSubjectKeyIdentifierLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainSetScp11Allowlist)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kid,
  CK_BYTE kvn,
  const PKCS11RS_BYTE_BUFFER *pSerials,
  CK_ULONG ulSerialCount
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SecurityDomainDeleteScp11Key)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE kid,
  CK_BYTE kvn,
  CK_BBOOL deleteLast
);

#define PKCS11RS_YUBIHSM_DEVICE_FINGERPRINT_SIZE 32

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_YubiHsmEnrollDeviceAttestation)(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulAttestationKeyId,
  CK_BYTE_PTR pFingerprint,
  CK_ULONG_PTR pulFingerprintLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_YubiHsmEnrollDeviceYubicoAttestation)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pFingerprint,
  CK_ULONG_PTR pulFingerprintLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_YubiHsmEnrollDevicePublicKey)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pFingerprint,
  CK_ULONG_PTR pulFingerprintLen
);

#ifdef __cplusplus
}
#endif

#endif /* PKCS11RS_H */
