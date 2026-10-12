/* Signed-process fixture for native platform lifecycle and HSM provisioning. */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#define NULL_PTR 0
#include "pkcs11rs.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOAD(name) __typeof__(&name) p_##name = dlsym(module, #name); if (!p_##name) return 2
#define CHECK(name, ...) do { CK_RV rv = p_##name(__VA_ARGS__); \
  printf("%s %lu\n", #name, rv); fflush(stdout); if (rv != CKR_OK) { result = 1; goto cleanup; } } while (0)

int main(int argc, char **argv) {
  if (argc != 4) return 2;
  void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!module) { fprintf(stderr, "%s\n", dlerror()); return 2; }
  LOAD(C_Initialize); LOAD(C_Finalize); LOAD(C_GetSlotList); LOAD(C_GetTokenInfo);
  LOAD(C_OpenSession); LOAD(C_Login); LOAD(C_Logout); LOAD(C_CloseSession);
  LOAD(PKCS11RS_PlatformCredentialGenerate); LOAD(PKCS11RS_PlatformCredentialGetPublicKey);
  LOAD(PKCS11RS_PlatformCredentialList); LOAD(PKCS11RS_PlatformCredentialDelete);
  LOAD(PKCS11RS_YubiHsmProvisionPlatformCredential); LOAD(PKCS11RS_YubiHsmUnprovisionPlatformCredential);
  int result = 0, generated = 0, provisioned = 0;
  CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
  CK_ULONG authkey = strtoul(argv[3], NULL, 16), size = 65, count = 0, outcome = 0;
  CK_BYTE public_key[65], read_key[65], capabilities[8] = {0};
  char name[100]; snprintf(name, sizeof name, "pkcs11rs-native-header-%ld", (long)getpid());
  char configuration[700];
  snprintf(configuration, sizeof configuration,
    "{\"version\":1,\"hardware\":{\"discovery\":true},\"slots\":{\"serials\":[\"%s\"]},"
    "\"ccid\":{\"applications\":[\"hsmauth\"]},\"software\":{\"slots\":[]},"
    "\"platform\":{\"enabled\":false},\"yubihsm\":{\"urls\":[],\"recreate_sessions\":false}}", argv[2]);
  CK_C_INITIALIZE_ARGS args = {0}; args.pReserved = configuration;
  CHECK(C_Initialize, &args);
  CHECK(C_GetSlotList, CK_TRUE, NULL, &count);
  CK_SLOT_ID *slots = calloc(count, sizeof *slots);
  if (!slots) { result = 2; goto cleanup; }
  CK_RV rv = p_C_GetSlotList(CK_TRUE, slots, &count);
  CK_SLOT_ID target = CK_UNAVAILABLE_INFORMATION;
  for (CK_ULONG i = 0; rv == CKR_OK && i < count; ++i) {
    CK_TOKEN_INFO info;
    if (p_C_GetTokenInfo(slots[i], &info) != CKR_OK) continue;
    size_t length = sizeof info.serialNumber;
    while (length && info.serialNumber[length - 1] == ' ') --length;
    if (strlen(argv[2]) == length && memcmp(argv[2], info.serialNumber, length) == 0)
      target = slots[i];
  }
  free(slots);
  if (target == CK_UNAVAILABLE_INFORMATION) { result = 2; goto cleanup; }
  CHECK(C_OpenSession, target, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
  CK_UTF8CHAR pin[] = "0001password";
  rv = p_C_Login(session, CKU_USER, pin, sizeof pin - 1);
  memset(pin, 0, sizeof pin);
  printf("C_Login %lu\n", rv);
  if (rv != CKR_OK) { result = 1; goto cleanup; }
  CHECK(PKCS11RS_PlatformCredentialGenerate, (CK_UTF8CHAR *)name, strlen(name), public_key, &size);
  generated = 1;
  CHECK(PKCS11RS_PlatformCredentialGetPublicKey, (CK_UTF8CHAR *)name, strlen(name), read_key, &size);
  if (size != 65 || memcmp(public_key, read_key, 65)) { result = 1; goto cleanup; }
  CHECK(PKCS11RS_PlatformCredentialList, NULL, &count);
  PKCS11RS_PLATFORM_CREDENTIAL_INFO *entries = calloc(count, sizeof *entries);
  if (!entries) { result = 2; goto cleanup; }
  rv = p_PKCS11RS_PlatformCredentialList(entries, &count);
  printf("PKCS11RS_PlatformCredentialList %lu\n", rv);
  int found = 0;
  for (CK_ULONG i = 0; rv == CKR_OK && i < count; ++i)
    if (entries[i].ulNameLen == strlen(name) && !memcmp(entries[i].name, name, strlen(name)))
      found = entries[i].ulAlgorithm == PKCS11RS_PLATFORM_CREDENTIAL_ALGORITHM_P256;
  free(entries);
  if (!found) { result = 1; goto cleanup; }
  for (CK_ULONG expected = PKCS11RS_PLATFORM_PROVISIONED; expected <= PKCS11RS_PLATFORM_ALREADY_PROVISIONED; ++expected) {
    CHECK(PKCS11RS_YubiHsmProvisionPlatformCredential, session, (CK_UTF8CHAR *)name, strlen(name), authkey,
      (CK_UTF8CHAR *)"pkcs11rs header test", 19, 0xffff, capabilities, 8, capabilities, 8, &outcome);
    provisioned = 1;
    if (outcome != expected) { result = 1; goto cleanup; }
  }
  CHECK(PKCS11RS_YubiHsmUnprovisionPlatformCredential, session, (CK_UTF8CHAR *)name, strlen(name), authkey);
  provisioned = 0;
  CHECK(PKCS11RS_YubiHsmUnprovisionPlatformCredential, session, (CK_UTF8CHAR *)name, strlen(name), authkey);
  CHECK(PKCS11RS_PlatformCredentialDelete, (CK_UTF8CHAR *)name, strlen(name));
  generated = 0;
cleanup:
  if (provisioned) result |= p_PKCS11RS_YubiHsmUnprovisionPlatformCredential(session, (CK_UTF8CHAR *)name, strlen(name), authkey) != CKR_OK;
  if (generated) result |= p_PKCS11RS_PlatformCredentialDelete((CK_UTF8CHAR *)name, strlen(name)) != CKR_OK;
  if (session != CK_INVALID_HANDLE) { p_C_Logout(session); p_C_CloseSession(session); }
  p_C_Finalize(NULL); dlclose(module);
  return result;
}
