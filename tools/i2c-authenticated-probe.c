/* Non-mutating I2C lab probe. Existing Secure Enclave credential only.
 * No key creation/import/deletion, raw APDUs, or local hardware discovery.
 * Build on macOS and sign the host for the existing platform credential group.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define CK_PTR *
#define CK_DECLARE_FUNCTION(r, n) r n
#define CK_DECLARE_FUNCTION_POINTER(r, n) r(*n)
#define CK_CALLBACK_FUNCTION(r, n) r(*n)
#define NULL_PTR 0
#include "pkcs11.h"
#define LOAD(name)                                                             \
  CK_##name name = (CK_##name)dlsym(lib, #name);                               \
  if (!name) {                                                                 \
    fprintf(stderr, "missing %s\n", #name);                                    \
    return 2;                                                                  \
  }
#define REQUIRE(call)                                                          \
  do {                                                                         \
    CK_RV r = (call);                                                          \
    if (r != CKR_OK) {                                                         \
      fprintf(stderr, "%s: 0x%lx\n", #call, r);                                \
      status = 1;                                                              \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)
static double seconds(clockid_t clock) {
  struct timespec t;
  clock_gettime(clock, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}
static void hex(const unsigned char *p, CK_ULONG n) {
  for (CK_ULONG i = 0; i < n; i++)
    printf("%02x", p[i]);
}
static int unhex(const char *s, unsigned char *out, size_t *length) {
  size_t n = strlen(s);
  if (!n || n % 2 || n > 128)
    return 0;
  for (size_t i = 0; i < n / 2; i++) {
    char pair[3] = {s[2 * i], s[2 * i + 1], 0}, *end;
    unsigned long v = strtoul(pair, &end, 16);
    if (*end)
      return 0;
    out[i] = (unsigned char)v;
  }
  *length = n / 2;
  return 1;
}
int main(int argc, char **argv) {
  if (argc < 6 || argc > 8) {
    fprintf(stderr, "Usage: probe LIB URL SERIAL inventory|read|sign COUNT "
                    "[KEY_ID_HEX|-] [BARRIER_DIRECTORY]\n");
    return 2;
  }
  if (strcmp(argv[3], "24000001") && strcmp(argv[3], "25000002"))
    return 2;
  if (strcmp(argv[4], "inventory") && strcmp(argv[4], "read") &&
      strcmp(argv[4], "sign"))
    return 2;
  if (strncmp(argv[2], "http://", 7) || strpbrk(argv[2], "\"\\"))
    return 2;
  char *end;
  unsigned long count = strtoul(argv[5], &end, 10);
  if (*end || !count || count > 10000)
    return 2;
  unsigned char wanted_id[64];
  size_t wanted_length = 0;
  if (!strcmp(argv[4], "sign") &&
      (argc < 7 || !unhex(argv[6], wanted_id, &wanted_length)))
    return 2;
  void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!lib) {
    fprintf(stderr, "%s\n", dlerror());
    return 2;
  }
  LOAD(C_Initialize);
  LOAD(C_Finalize);
  LOAD(C_GetSlotList);
  LOAD(C_GetTokenInfo);
  LOAD(C_OpenSession);
  LOAD(C_CloseSession);
  LOAD(C_Login);
  LOAD(C_LoginUser);
  LOAD(C_GetSessionInfo);
  LOAD(C_FindObjectsInit);
  LOAD(C_FindObjects);
  LOAD(C_FindObjectsFinal);
  LOAD(C_GetAttributeValue);
  LOAD(C_SignInit);
  LOAD(C_Sign);
  LOAD(C_VerifyInit);
  LOAD(C_Verify);
  int status = 0, initialized = 0;
  CK_SESSION_HANDLE source = 0, target = 0;
  char configuration[2048], target_label[64];
  int length =
      snprintf(configuration, sizeof(configuration),
               "{\"version\":1,\"hardware\":{\"discovery\":false},\"platform\":"
               "{\"enabled\":true},\"slots\":{\"serials\":[\"%s\"]},"
               "\"yubihsm\":{\"urls\":[\"%s\"],\"recreate_sessions\":false},"
               "\"ccid\":{\"applications\":[\"piv\"]}}",
               argv[3], argv[2]);
  if (length < 0 || (size_t)length >= sizeof(configuration))
    return 2;
  snprintf(target_label, sizeof(target_label), "YubiHSM #%s", argv[3]);
  setvbuf(stdout, NULL, _IOLBF, 0);
  CK_C_INITIALIZE_ARGS init = {0};
  init.flags = CKF_OS_LOCKING_OK;
  init.pReserved = configuration;
  REQUIRE(C_Initialize(&init));
  initialized = 1;
  CK_SLOT_ID slots[32];
  CK_ULONG slot_count = 32;
  REQUIRE(C_GetSlotList(CK_TRUE, slots, &slot_count));
  if (slot_count > 32) {
    status = 2;
    goto cleanup;
  }
  for (CK_ULONG i = 0; i < slot_count; i++) {
    CK_TOKEN_INFO info;
    REQUIRE(C_GetTokenInfo(slots[i], &info));
    if (!memcmp(info.label, "Secure Enclave", 14)) {
      REQUIRE(C_OpenSession(slots[i], CKF_SERIAL_SESSION, NULL, NULL, &source));
      REQUIRE(C_Login(source, CKU_USER, NULL, 0));
    } else if (!memcmp(info.label, target_label, strlen(target_label))) {
      REQUIRE(C_OpenSession(slots[i], CKF_SERIAL_SESSION, NULL, NULL, &target));
    }
  }
  if (!source || !target) {
    fprintf(stderr, "source or target missing\n");
    status = 2;
    goto cleanup;
  }
  CK_UTF8CHAR credential[] = "pkcs11:token=Secure%20Enclave;object=reserve;"
                             "type=private?pkcs11rs-authkey=1003";
  REQUIRE(C_LoginUser(target, CKU_USER, NULL, 0, credential,
                      sizeof(credential) - 1));
  CK_OBJECT_HANDLE private_key = 0, public_key = 0;
  unsigned private_matches = 0, public_matches = 0;
  if (!strcmp(argv[4], "inventory") || !strcmp(argv[4], "sign")) {
    REQUIRE(C_FindObjectsInit(target, NULL, 0));
    for (;;) {
      CK_OBJECT_HANDLE objects[64];
      CK_ULONG found = 0;
      REQUIRE(C_FindObjects(target, objects, 64, &found));
      if (!found)
        break;
      for (CK_ULONG i = 0; i < found; i++) {
        CK_OBJECT_CLASS klass = 0;
        CK_KEY_TYPE type = ~(CK_KEY_TYPE)0;
        CK_ULONG bits = 0;
        CK_BBOOL can_sign = CK_FALSE;
        unsigned char id[64] = {0}, label[256] = {0};
        CK_ATTRIBUTE a[] = {{CKA_CLASS, &klass, sizeof(klass)},
                            {CKA_KEY_TYPE, &type, sizeof(type)},
                            {CKA_MODULUS_BITS, &bits, sizeof(bits)},
                            {CKA_SIGN, &can_sign, sizeof(can_sign)},
                            {CKA_ID, id, sizeof(id)},
                            {CKA_LABEL, label, sizeof(label)}};
        for (size_t j = 0; j < sizeof(a) / sizeof(a[0]); j++) {
          CK_RV rv = C_GetAttributeValue(target, objects[i], &a[j], 1);
          if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID &&
              rv != CKR_ATTRIBUTE_SENSITIVE) {
            fprintf(stderr, "inventory attribute: 0x%lx\n", rv);
            status = 1;
            goto cleanup;
          }
        }
        CK_ULONG id_len = a[4].ulValueLen, label_len = a[5].ulValueLen;
        if (id_len > sizeof(id))
          id_len = 0;
        if (label_len > sizeof(label))
          label_len = 0;
        if (!strcmp(argv[4], "inventory")) {
          printf("{\"kind\":\"object\",\"serial\":\"%s\",\"class\":%lu,\"key_"
                 "type\":%lu,\"rsa_bits\":%lu,\"can_sign\":%s,\"id\":\"",
                 argv[3], klass, type, bits, can_sign ? "true" : "false");
          hex(id, id_len);
          printf("\",\"label_hex\":\"");
          hex(label, label_len);
          printf("\"}\n");
        }
        if (!strcmp(argv[4], "sign") && type == CKK_RSA &&
            id_len == wanted_length && !memcmp(id, wanted_id, id_len)) {
          if (klass == CKO_PRIVATE_KEY && can_sign) {
            private_key = objects[i];
            private_matches++;
          }
          if (klass == CKO_PUBLIC_KEY) {
            public_key = objects[i];
            public_matches++;
          }
        }
      }
    }
    REQUIRE(C_FindObjectsFinal(target));
  }
  if (!strcmp(argv[4], "inventory"))
    goto cleanup;
  if (!strcmp(argv[4], "sign") &&
      (private_matches != 1 || public_matches != 1)) {
    fprintf(stderr, "requires one existing RSA signing pair, found %u/%u\n",
            private_matches, public_matches);
    status = 2;
    goto cleanup;
  }
  printf("{\"kind\":\"ready\",\"serial\":\"%s\",\"mode\":\"%s\"}\n", argv[3],
         argv[4]);
  if (argc == 8) {
    char path[2048];
    int n = snprintf(path, sizeof(path), "%s/%s.ready", argv[7], argv[3]);
    if (n < 0 || (size_t)n >= sizeof(path)) {
      status = 2;
      goto cleanup;
    }
    FILE *f = fopen(path, "w");
    if (!f) {
      perror("ready file");
      status = 2;
      goto cleanup;
    }
    fputs("ready\n", f);
    fclose(f);
    n = snprintf(path, sizeof(path), "%s/start", argv[7]);
    if (n < 0 || (size_t)n >= sizeof(path)) {
      status = 2;
      goto cleanup;
    }
    double deadline = seconds(CLOCK_MONOTONIC) + 120;
    while (access(path, F_OK) != 0) {
      if (seconds(CLOCK_MONOTONIC) > deadline) {
        fprintf(stderr, "barrier timeout\n");
        status = 2;
        goto cleanup;
      }
      usleep(10000);
    }
  }
  for (unsigned long index = 0; index < count; index++) {
    double sent = seconds(CLOCK_REALTIME), started = seconds(CLOCK_MONOTONIC);
    CK_RV rv;
    if (!strcmp(argv[4], "read")) {
      CK_SESSION_INFO info;
      rv = C_GetSessionInfo(target, &info);
    } else {
      unsigned char message[64] = "pkcs11rs I2C non-mutating peer timing probe",
                    signature[1024];
      for (unsigned j = 0; j < 8; j++)
        message[56 + j] = (unsigned char)(index >> (8 * (7 - j)));
      CK_MECHANISM mechanism = {CKM_SHA256_RSA_PKCS, NULL, 0};
      CK_ULONG signature_len = sizeof(signature);
      rv = C_SignInit(target, &mechanism, private_key);
      if (rv == CKR_OK)
        rv =
            C_Sign(target, message, sizeof(message), signature, &signature_len);
      if (rv == CKR_OK)
        rv = C_VerifyInit(target, &mechanism, public_key);
      if (rv == CKR_OK)
        rv = C_Verify(target, message, sizeof(message), signature,
                      signature_len);
    }
    printf(
        "{\"kind\":\"operation\",\"serial\":\"%s\",\"mode\":\"%s\",\"index\":%"
        "lu,\"sent\":%.6f,\"received\":%.6f,\"elapsed_us\":%.0f,\"rv\":%lu}\n",
        argv[3], argv[4], index, sent, seconds(CLOCK_REALTIME),
        (seconds(CLOCK_MONOTONIC) - started) * 1e6, rv);
    if (rv != CKR_OK) {
      status = 1;
      break;
    }
  }
cleanup:
  if (target && C_CloseSession(target) != CKR_OK)
    status = 1;
  if (source && C_CloseSession(source) != CKR_OK)
    status = 1;
  if (initialized && C_Finalize(NULL) != CKR_OK)
    status = 1;
  dlclose(lib);
  return status;
}
