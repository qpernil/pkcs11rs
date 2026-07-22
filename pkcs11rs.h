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

#ifdef __cplusplus
}
#endif

#endif /* PKCS11RS_H */
