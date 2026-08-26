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

#define PKCS11RS_YUBICO_BASE_VENDOR 0x59554200UL
#define CKK_YUBICO_AES128_CCM_WRAP \
  (CKK_VENDOR_DEFINED | PKCS11RS_YUBICO_BASE_VENDOR | 29UL)
#define CKK_YUBICO_AES192_CCM_WRAP \
  (CKK_VENDOR_DEFINED | PKCS11RS_YUBICO_BASE_VENDOR | 41UL)
#define CKK_YUBICO_AES256_CCM_WRAP \
  (CKK_VENDOR_DEFINED | PKCS11RS_YUBICO_BASE_VENDOR | 42UL)
#define CKM_YUBICO_AES_CCM_WRAP \
  (CKM_VENDOR_DEFINED | PKCS11RS_YUBICO_BASE_VENDOR | 4UL)
#define CKM_YUBICO_RSA_WRAP \
  (CKM_VENDOR_DEFINED | PKCS11RS_YUBICO_BASE_VENDOR | 9UL)

#define PKCS11RS_VENDOR_BASE 0x50530000UL
#define CKM_PKCS11RS_PREVIEW_SIGN_KEY_PAIR_GEN \
  (CKM_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 1UL)
#define CKM_PKCS11RS_PREVIEW_SIGN_DERIVE \
  (CKM_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 2UL)
#define CKM_PKCS11RS_PREVIEW_SIGN \
  (CKM_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 3UL)
#define CKM_PKCS11RS_PROJECT_PUBLIC_KEY \
  (CKM_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 4UL)
#define CKM_PKCS11RS_FIDO_ASSERTION \
  (CKM_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 5UL)
#define CKM_PKCS11RS_PREFIXED_ECDH_DERIVE \
  (CKM_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 6UL)
#define CKK_PKCS11RS_PREVIEW_SIGN_REGISTRATION \
  (CKK_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 1UL)
#define CKA_PKCS11RS_PREVIEW_SIGN_REGISTRATION \
  (CKA_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 1UL)
#define CKA_PKCS11RS_PREVIEW_SIGN_DERIVED_KEY \
  (CKA_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 2UL)
#define CKA_PKCS11RS_FIDO_RP_ID \
  (CKA_VENDOR_DEFINED | PKCS11RS_VENDOR_BASE | 3UL)

typedef struct CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrefixDataLen;
  CK_BYTE_PTR pPrefixData;
} CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS;

typedef CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS CK_PTR
  CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS_PTR;

/*
 * Return the canonical CKM_* name for a mechanism recognized by this build.
 * The returned string is NUL-terminated, immutable, owned by the library, and
 * valid for the lifetime of the process. An unknown mechanism returns NULL.
 */
CK_DECLARE_FUNCTION(const char *, PKCS11RS_GetMechanismName)(
  CK_MECHANISM_TYPE type
);

/*
 * Return canonical names for other enum-like PKCS #11 values. These functions
 * use the same ownership, lifetime, and unknown-value contract as
 * PKCS11RS_GetMechanismName.
 */
CK_DECLARE_FUNCTION(const char *, PKCS11RS_GetReturnValueName)(CK_RV value);
CK_DECLARE_FUNCTION(const char *, PKCS11RS_GetObjectClassName)(
  CK_OBJECT_CLASS value
);
CK_DECLARE_FUNCTION(const char *, PKCS11RS_GetKeyTypeName)(CK_KEY_TYPE value);
CK_DECLARE_FUNCTION(const char *, PKCS11RS_GetAttributeTypeName)(
  CK_ATTRIBUTE_TYPE value
);
CK_DECLARE_FUNCTION(const char *, PKCS11RS_GetProfileIdName)(
  CK_PROFILE_ID value
);

typedef struct CKM_YUBICO_AES_CCM_WRAP_PARAMS {
  CK_ULONG format;
} CKM_YUBICO_AES_CCM_WRAP_PARAMS;

typedef CKM_YUBICO_AES_CCM_WRAP_PARAMS CK_PTR
  CKM_YUBICO_AES_CCM_WRAP_PARAMS_PTR;

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

#define PKCS11RS_HSMAUTH_P256_PUBLIC_KEY_SIZE 65

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthPutSymmetricCredential)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pLabel,
  CK_ULONG ulLabelLen,
  const CK_BYTE *pEncKey,
  CK_ULONG ulEncKeyLen,
  const CK_BYTE *pMacKey,
  CK_ULONG ulMacKeyLen,
  const CK_UTF8CHAR *pCredentialPassword,
  CK_ULONG ulCredentialPasswordLen,
  CK_BBOOL touchRequired
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthPutDerivedSymmetricCredential)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pLabel,
  CK_ULONG ulLabelLen,
  const CK_UTF8CHAR *pDerivationPassword,
  CK_ULONG ulDerivationPasswordLen,
  const CK_UTF8CHAR *pCredentialPassword,
  CK_ULONG ulCredentialPasswordLen,
  CK_BBOOL touchRequired
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthPutAsymmetricCredential)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pLabel,
  CK_ULONG ulLabelLen,
  const CK_BYTE *pPrivateKey,
  CK_ULONG ulPrivateKeyLen,
  const CK_UTF8CHAR *pCredentialPassword,
  CK_ULONG ulCredentialPasswordLen,
  CK_BBOOL touchRequired,
  CK_BYTE_PTR pPublicKey,
  CK_ULONG_PTR pulPublicKeyLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthPutDerivedAsymmetricCredential)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pLabel,
  CK_ULONG ulLabelLen,
  const CK_UTF8CHAR *pDerivationPassword,
  CK_ULONG ulDerivationPasswordLen,
  const CK_UTF8CHAR *pCredentialPassword,
  CK_ULONG ulCredentialPasswordLen,
  CK_BBOOL touchRequired,
  CK_BYTE_PTR pPublicKey,
  CK_ULONG_PTR pulPublicKeyLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthGenerateAsymmetricCredential)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pLabel,
  CK_ULONG ulLabelLen,
  const CK_UTF8CHAR *pCredentialPassword,
  CK_ULONG ulCredentialPasswordLen,
  CK_BBOOL touchRequired,
  CK_BYTE_PTR pPublicKey,
  CK_ULONG_PTR pulPublicKeyLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthDeleteCredential)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pLabel,
  CK_ULONG ulLabelLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthChangeCredentialPassword)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pLabel,
  CK_ULONG ulLabelLen,
  const CK_UTF8CHAR *pNewCredentialPassword,
  CK_ULONG ulNewCredentialPasswordLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthChangeManagementPassword)(
  CK_SESSION_HANDLE hSession,
  const CK_UTF8CHAR *pNewManagementPassword,
  CK_ULONG ulNewManagementPasswordLen
);

CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_HsmAuthReset)(
  CK_SESSION_HANDLE hSession
);

/*
 * Export an extractable private key from a named software slot as a DER
 * PKCS #8 EncryptedPrivateKeyInfo. The session must have an active CKU_USER
 * login. The export password must contain 8 through 1024 bytes.
 *
 * PBES2 uses scrypt (N=16384, r=8, p=1) and AES-256-CBC. The decrypted
 * OneAsymmetricKey includes PKCS #9 friendlyName/localKeyId attributes and
 * pkcs11rs' private attribute payload.
 *
 * If pEncryptedKey is NULL, pulEncryptedKeyLen receives the required length.
 * If the supplied buffer is too small, the function returns
 * CKR_BUFFER_TOO_SMALL and updates pulEncryptedKeyLen.
 */
CK_DECLARE_FUNCTION(CK_RV, PKCS11RS_SoftwareExportPrivateKey)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey,
  const CK_UTF8CHAR *pPassword,
  CK_ULONG ulPasswordLen,
  CK_BYTE_PTR pEncryptedKey,
  CK_ULONG_PTR pulEncryptedKeyLen
);

#ifdef __cplusplus
}
#endif

#endif /* PKCS11RS_H */
