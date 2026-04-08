// Generates test certificates for Envoy integration tests using BoringSSL APIs.
// No openssl CLI dependency — runs as a Bazel genrule tool.
//
// Usage: generate_test_certs <output_dir>
//
// Produces all standard test cert/key PEM pairs, certificate chains,
// OCSP responses (.der), and C++ info/hash header files consumed by tests.

#include <cassert>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "openssl/asn1.h"
#include "openssl/base.h"
#include "openssl/base64.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/bytestring.h"
#include "openssl/ec_key.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

namespace {

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

void Die(const std::string& msg) {
  fprintf(stderr, "FATAL: %s\n", msg.c_str());
  exit(1);
}

std::string P(const std::string& dir, const std::string& name) {
  return dir + "/" + name;
}

void WriteFile(const std::string& path, const std::string& content) {
  std::ofstream f(path, std::ios::binary);
  if (!f) Die("Cannot open for writing: " + path);
  f << content;
}

void WriteDer(const std::string& path, const std::vector<uint8_t>& der) {
  std::ofstream f(path, std::ios::binary);
  if (!f) Die("Cannot open for writing: " + path);
  f.write(reinterpret_cast<const char*>(der.data()), der.size());
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

bssl::UniquePtr<EVP_PKEY> MakeRSAKey(int bits = 2048) {
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
    Die("RSA keygen ctx init failed");
  }
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) Die("RSA keygen failed");
  return bssl::UniquePtr<EVP_PKEY>(pkey);
}

bssl::UniquePtr<EVP_PKEY> MakeECKey(int nid) {
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid) <= 0) {
    Die("EC keygen ctx init failed");
  }
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) Die("EC keygen failed");
  return bssl::UniquePtr<EVP_PKEY>(pkey);
}

// ---------------------------------------------------------------------------
// Subject name
// ---------------------------------------------------------------------------

bssl::UniquePtr<X509_NAME> MakeSubject(const std::string& cn,
                                        const std::string& email = "") {
  bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
  auto add = [&](const char* field, const std::string& val) {
    X509_NAME_add_entry_by_txt(name.get(), field, MBSTRING_ASC,
                               reinterpret_cast<const uint8_t*>(val.c_str()),
                               -1, -1, 0);
  };
  add("C", "US");
  add("ST", "California");
  add("L", "San Francisco");
  add("O", "Lyft");
  add("OU", "Lyft Engineering");
  add("CN", cn);
  if (!email.empty()) add("emailAddress", email);
  return name;
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

void AddExt(X509* cert, X509* issuer, int nid, const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  bssl::UniquePtr<X509_EXTENSION> ext(
      X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value));
  if (!ext) Die(std::string("Failed extension ") + OBJ_nid2sn(nid) + "=" + value);
  X509_add_ext(cert, ext.get(), -1);
}

// ---------------------------------------------------------------------------
// Certificate builder
// ---------------------------------------------------------------------------

static uint64_t g_serial = 1;

struct CertConfig {
  std::string cn;
  std::string email;
  bool is_ca = false;
  int pathlen = -1;
  std::string key_usage;
  std::string ext_key_usage;
  std::string san;
  int days = 3650;
};

bssl::UniquePtr<X509> MakeCert(EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key,
                                const CertConfig& cfg) {
  bssl::UniquePtr<X509> x509(X509_new());
  if (!x509) Die("X509_new");
  X509_set_version(x509.get(), 2);

  bssl::UniquePtr<ASN1_INTEGER> serial(ASN1_INTEGER_new());
  ASN1_INTEGER_set_uint64(serial.get(), g_serial++);
  X509_set_serialNumber(x509.get(), serial.get());

  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()),
                  static_cast<long>(cfg.days) * 24 * 3600);

  bssl::UniquePtr<X509_NAME> subj = MakeSubject(cfg.cn, cfg.email);
  X509_set_subject_name(x509.get(), subj.get());
  if (issuer) {
    X509_set_issuer_name(x509.get(), X509_get_subject_name(issuer));
  } else {
    X509_set_issuer_name(x509.get(), subj.get());
  }
  X509_set_pubkey(x509.get(), key);

  std::string bc = cfg.is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE";
  if (cfg.is_ca && cfg.pathlen >= 0)
    bc += ",pathlen:" + std::to_string(cfg.pathlen);
  AddExt(x509.get(), issuer, NID_basic_constraints, bc.c_str());
  AddExt(x509.get(), issuer, NID_subject_key_identifier, "hash");
  if (issuer) AddExt(x509.get(), issuer, NID_authority_key_identifier, "keyid:always");
  if (!cfg.key_usage.empty())
    AddExt(x509.get(), issuer, NID_key_usage, cfg.key_usage.c_str());
  if (!cfg.ext_key_usage.empty())
    AddExt(x509.get(), issuer, NID_ext_key_usage, cfg.ext_key_usage.c_str());
  if (!cfg.san.empty())
    AddExt(x509.get(), issuer, NID_subject_alt_name, cfg.san.c_str());

  EVP_PKEY* signing_key = issuer_key ? issuer_key : key;
  if (!X509_sign(x509.get(), signing_key, EVP_sha256()))
    Die("X509_sign failed for " + cfg.cn);
  return x509;
}

// ---------------------------------------------------------------------------
// PEM writers
// ---------------------------------------------------------------------------

std::string PemCert(X509* cert) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  PEM_write_bio_X509(bio.get(), cert);
  const uint8_t* data;
  size_t len;
  BIO_mem_contents(bio.get(), &data, &len);
  return std::string(reinterpret_cast<const char*>(data), len);
}

std::string PemKey(EVP_PKEY* key) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr);
  const uint8_t* data;
  size_t len;
  BIO_mem_contents(bio.get(), &data, &len);
  return std::string(reinterpret_cast<const char*>(data), len);
}

// ---------------------------------------------------------------------------
// Hash / encoding helpers
// ---------------------------------------------------------------------------

std::string ToHex(const uint8_t* data, size_t len) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out += kHex[(data[i] >> 4) & 0xf];
    out += kHex[data[i] & 0xf];
  }
  return out;
}

std::string ToBase64(const uint8_t* data, size_t len) {
  size_t out_len = 0;
  if (!EVP_EncodedLength(&out_len, len)) Die("EVP_EncodedLength");
  std::vector<uint8_t> buf(out_len);
  size_t written = EVP_EncodeBlock(buf.data(), data, len);
  // EVP_EncodeBlock writes a NUL terminator; written is the length without it.
  return std::string(reinterpret_cast<const char*>(buf.data()), written);
}

std::vector<uint8_t> CertDer(X509* cert) {
  int len = i2d_X509(cert, nullptr);
  if (len <= 0) Die("i2d_X509");
  std::vector<uint8_t> der(len);
  uint8_t* p = der.data();
  i2d_X509(cert, &p);
  return der;
}

std::string Sha256Hex(X509* cert) {
  std::vector<uint8_t> der = CertDer(cert);
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(der.data(), der.size(), digest);
  return ToHex(digest, SHA256_DIGEST_LENGTH);
}

std::string Sha1Hex(X509* cert) {
  std::vector<uint8_t> der = CertDer(cert);
  uint8_t digest[SHA_DIGEST_LENGTH];
  SHA1(der.data(), der.size(), digest);
  return ToHex(digest, SHA_DIGEST_LENGTH);
}

std::string FingerprintSha256(X509* cert) {
  std::vector<uint8_t> der = CertDer(cert);
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(der.data(), der.size(), digest);
  std::string out;
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    static const char kHex[] = "0123456789ABCDEF";
    if (i) out += ':';
    out += kHex[(digest[i] >> 4) & 0xf];
    out += kHex[digest[i] & 0xf];
  }
  return out;
}

std::string SpkiSha256Base64(EVP_PKEY* key) {
  int len = i2d_PUBKEY(key, nullptr);
  if (len <= 0) Die("i2d_PUBKEY");
  std::vector<uint8_t> der(len);
  uint8_t* p = der.data();
  i2d_PUBKEY(key, &p);
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(der.data(), der.size(), digest);
  return ToBase64(digest, SHA256_DIGEST_LENGTH);
}

std::string SerialHex(X509* cert) {
  const ASN1_INTEGER* serial = X509_get_serialNumber(cert);
  bssl::UniquePtr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial, nullptr));
  char* hex = BN_bn2hex(bn.get());
  std::string result(hex);
  OPENSSL_free(hex);
  for (char& c : result) {
    if (c >= 'A' && c <= 'F') c += 32;
  }
  return result;
}

std::string Asn1TimeStr(const ASN1_TIME* t) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  ASN1_TIME_print(bio.get(), t);
  const uint8_t* data;
  size_t len;
  BIO_mem_contents(bio.get(), &data, &len);
  return std::string(reinterpret_cast<const char*>(data), len);
}

// ---------------------------------------------------------------------------
// Header writers
// ---------------------------------------------------------------------------

void WriteInfoHeader(const std::string& path, const std::string& prefix, X509* cert) {
  std::ostringstream ss;
  ss << "// NOLINT(namespace-envoy)\n";
  ss << "constexpr char " << prefix << "_CERT_256_HASH[] =\n";
  ss << "    \"" << Sha256Hex(cert) << "\";\n";
  ss << "constexpr char " << prefix << "_CERT_1_HASH[] = \"" << Sha1Hex(cert) << "\";\n";
  ss << "constexpr char " << prefix << "_CERT_SPKI[] = \""
     << SpkiSha256Base64(X509_get_pubkey(cert)) << "\";\n";
  ss << "constexpr char " << prefix << "_CERT_SERIAL[] = \"" << SerialHex(cert) << "\";\n";
  ss << "constexpr char " << prefix << "_CERT_NOT_BEFORE[] = \""
     << Asn1TimeStr(X509_get_notBefore(cert)) << "\";\n";
  ss << "constexpr char " << prefix << "_CERT_NOT_AFTER[] = \""
     << Asn1TimeStr(X509_get_notAfter(cert)) << "\";\n";
  WriteFile(path, ss.str());
}

void WriteHashHeader(const std::string& path, const std::string& prefix, X509* cert) {
  std::ostringstream ss;
  ss << "// NOLINT(namespace-envoy)\n";
  ss << "constexpr char " << prefix << "_CERT_HASH[] = \"" << FingerprintSha256(cert)
     << "\";\n";
  WriteFile(path, ss.str());
}

// ---------------------------------------------------------------------------
// Signing helper
// ---------------------------------------------------------------------------

std::vector<uint8_t> Sign(const uint8_t* data, size_t data_len, EVP_PKEY* key) {
  bssl::UniquePtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
  size_t sig_len = 0;
  if (!ctx ||
      !EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) ||
      !EVP_DigestSign(ctx.get(), nullptr, &sig_len, data, data_len)) {
    Die("EVP_DigestSign size failed");
  }
  std::vector<uint8_t> sig(sig_len);
  if (!EVP_DigestSign(ctx.get(), sig.data(), &sig_len, data, data_len)) {
    Die("EVP_DigestSign failed");
  }
  sig.resize(sig_len);
  return sig;
}

// ---------------------------------------------------------------------------
// OCSP response generation via raw CBB (no openssl/ocsp.h needed)
//
// Produces an OCSPResponse with:
//   - responseStatus: successful
//   - BasicOCSPResponse signed by the issuer key
//   - CertStatus: unknown (matches certs.sh behaviour — no CA index file)
//   - No nonce (standalone response, not tied to a specific request)
// ---------------------------------------------------------------------------

// GeneralizedTime string: "YYYYMMDDHHmmssZ"
std::string GeneralizedTimeNow(int offset_days = 0) {
  time_t t = time(nullptr) + static_cast<time_t>(offset_days) * 86400;
  struct tm tm_val {};
  gmtime_r(&t, &tm_val);
  char buf[16];
  strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", &tm_val);
  return std::string(buf);
}

// Finish a CBB and return its contents as a vector, freeing the internal buffer.
std::vector<uint8_t> CbbFinish(CBB* cbb) {
  uint8_t* data = nullptr;
  size_t len = 0;
  if (!CBB_finish(cbb, &data, &len)) Die("CBB_finish failed");
  std::vector<uint8_t> result(data, data + len);
  OPENSSL_free(data);
  return result;
}

// sha256WithRSAEncryption AlgorithmIdentifier DER (with NULL params)
static const uint8_t kSha256WithRSAAlgId[] = {
    0x30, 0x0d,                          // SEQUENCE, 13 bytes
    0x06, 0x09,                          // OID, 9 bytes
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, // 1.2.840.113549.
    0x01, 0x01, 0x0b,                    // .1.1.11
    0x05, 0x00,                          // NULL
};

// SHA-1 AlgorithmIdentifier DER (with NULL params)
static const uint8_t kSha1AlgId[] = {
    0x30, 0x07,                          // SEQUENCE, 7 bytes
    0x06, 0x05,                          // OID, 5 bytes
    0x2b, 0x0e, 0x03, 0x02, 0x1a,       // 1.3.14.3.2.26 (id-sha1)
    0x05, 0x00,                          // NULL
};

// id-pkix-ocsp-basic OID bytes (no tag/length; used inside OID TLV)
static const uint8_t kOcspBasicOidBytes[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
};

std::vector<uint8_t> MakeOcspResponse(X509* cert, X509* issuer, EVP_PKEY* issuer_key) {
  // --- CertID components ---
  // issuerNameHash = SHA1(DER-encoded issuer subject name)
  uint8_t issuer_name_hash[SHA_DIGEST_LENGTH];
  {
    uint8_t* der = nullptr;
    int len = i2d_X509_NAME(X509_get_subject_name(issuer), &der);
    if (len <= 0) Die("i2d_X509_NAME");
    SHA1(der, len, issuer_name_hash);
    OPENSSL_free(der);
  }

  // issuerKeyHash = SHA1(bit-string value of issuer's subjectPublicKey)
  uint8_t issuer_key_hash[SHA_DIGEST_LENGTH];
  {
    unsigned int klen = SHA_DIGEST_LENGTH;
    if (!X509_pubkey_digest(issuer, EVP_sha1(), issuer_key_hash, &klen)) {
      Die("X509_pubkey_digest");
    }
  }

  // serialNumber DER (INTEGER TLV)
  uint8_t* serial_der = nullptr;
  int serial_der_len = i2d_ASN1_INTEGER(X509_get_serialNumber(cert), &serial_der);
  if (serial_der_len <= 0) Die("i2d_ASN1_INTEGER");

  // issuer subject DER (for responderID byName)
  uint8_t* issuer_name_der = nullptr;
  int issuer_name_der_len = i2d_X509_NAME(X509_get_subject_name(issuer), &issuer_name_der);
  if (issuer_name_der_len <= 0) Die("i2d_X509_NAME issuer");

  const std::string produced_at = GeneralizedTimeNow();
  const std::string next_upd = GeneralizedTimeNow(3650);

  // --- Build ResponseData (tbsResponseData) ---
  CBB tbs_cbb;
  CBB_init(&tbs_cbb, 512);
  {
    CBB seq;
    if (!CBB_add_asn1(&tbs_cbb, &seq, CBS_ASN1_SEQUENCE)) Die("CBB seq");

    // responderID byName: [1] EXPLICIT Name
    // Tag A1 = context-specific [1] constructed
    CBB responder_id;
    if (!CBB_add_asn1(&seq, &responder_id,
                      CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 1)) {
      Die("CBB responderID");
    }
    if (!CBB_add_bytes(&responder_id, issuer_name_der, issuer_name_der_len)) {
      Die("CBB responderID name");
    }

    // producedAt GeneralizedTime (tag 0x18)
    CBB produced_at_cbb;
    if (!CBB_add_asn1(&seq, &produced_at_cbb, 0x18)) Die("CBB producedAt");
    if (!CBB_add_bytes(&produced_at_cbb,
                       reinterpret_cast<const uint8_t*>(produced_at.data()),
                       produced_at.size())) {
      Die("CBB producedAt data");
    }

    // responses SEQUENCE OF SingleResponse
    CBB responses;
    if (!CBB_add_asn1(&seq, &responses, CBS_ASN1_SEQUENCE)) Die("CBB responses");
    {
      CBB single;
      if (!CBB_add_asn1(&responses, &single, CBS_ASN1_SEQUENCE)) Die("CBB single");

      // CertID SEQUENCE
      CBB cert_id;
      if (!CBB_add_asn1(&single, &cert_id, CBS_ASN1_SEQUENCE)) Die("CBB certID");
      // hashAlgorithm (SHA-1 AlgId, already DER-encoded)
      if (!CBB_add_bytes(&cert_id, kSha1AlgId, sizeof(kSha1AlgId))) Die("CBB sha1");
      // issuerNameHash OCTET STRING
      CBB name_hash_cbb;
      if (!CBB_add_asn1(&cert_id, &name_hash_cbb, CBS_ASN1_OCTETSTRING)) Die("CBB nameHash");
      if (!CBB_add_bytes(&name_hash_cbb, issuer_name_hash, SHA_DIGEST_LENGTH)) {
        Die("CBB nameHash data");
      }
      // issuerKeyHash OCTET STRING
      CBB key_hash_cbb;
      if (!CBB_add_asn1(&cert_id, &key_hash_cbb, CBS_ASN1_OCTETSTRING)) Die("CBB keyHash");
      if (!CBB_add_bytes(&key_hash_cbb, issuer_key_hash, SHA_DIGEST_LENGTH)) {
        Die("CBB keyHash data");
      }
      // serialNumber INTEGER (raw DER TLV from i2d_ASN1_INTEGER)
      if (!CBB_add_bytes(&cert_id, serial_der, serial_der_len)) Die("CBB serial");

      // certStatus unknown: [2] IMPLICIT NULL = tag 0x82, length 0
      CBB unknown;
      if (!CBB_add_asn1(&single, &unknown, CBS_ASN1_CONTEXT_SPECIFIC | 2)) {
        Die("CBB unknown");
      }

      // thisUpdate GeneralizedTime
      CBB this_update;
      if (!CBB_add_asn1(&single, &this_update, 0x18)) Die("CBB thisUpdate");
      if (!CBB_add_bytes(&this_update,
                         reinterpret_cast<const uint8_t*>(produced_at.data()),
                         produced_at.size())) {
        Die("CBB thisUpdate data");
      }

      // nextUpdate [0] EXPLICIT GeneralizedTime
      CBB next_update_outer;
      if (!CBB_add_asn1(&single, &next_update_outer,
                        CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0)) {
        Die("CBB nextUpdate outer");
      }
      CBB next_update_inner;
      if (!CBB_add_asn1(&next_update_outer, &next_update_inner, 0x18)) {
        Die("CBB nextUpdate inner");
      }
      if (!CBB_add_bytes(&next_update_inner,
                         reinterpret_cast<const uint8_t*>(next_upd.data()),
                         next_upd.size())) {
        Die("CBB nextUpdate data");
      }
    }
  }
  std::vector<uint8_t> tbs = CbbFinish(&tbs_cbb);

  OPENSSL_free(issuer_name_der);
  OPENSSL_free(serial_der);

  // --- Sign tbsResponseData ---
  std::vector<uint8_t> sig = Sign(tbs.data(), tbs.size(), issuer_key);

  // --- Build BasicOCSPResponse ---
  CBB basic_cbb;
  CBB_init(&basic_cbb, 512);
  {
    CBB seq;
    if (!CBB_add_asn1(&basic_cbb, &seq, CBS_ASN1_SEQUENCE)) Die("CBB basic seq");
    // tbsResponseData (already DER-encoded)
    if (!CBB_add_bytes(&seq, tbs.data(), tbs.size())) Die("CBB tbs");
    // signatureAlgorithm
    if (!CBB_add_bytes(&seq, kSha256WithRSAAlgId, sizeof(kSha256WithRSAAlgId))) {
      Die("CBB sigAlg");
    }
    // signature BIT STRING: 0x00 (no unused bits) || sig bytes
    CBB sig_bs;
    if (!CBB_add_asn1(&seq, &sig_bs, CBS_ASN1_BITSTRING)) Die("CBB sig bs");
    if (!CBB_add_u8(&sig_bs, 0)) Die("CBB sig unused");
    if (!CBB_add_bytes(&sig_bs, sig.data(), sig.size())) Die("CBB sig data");
  }
  std::vector<uint8_t> basic = CbbFinish(&basic_cbb);

  // --- Wrap in OCSPResponse ---
  CBB resp_cbb;
  CBB_init(&resp_cbb, 64);
  {
    CBB seq;
    if (!CBB_add_asn1(&resp_cbb, &seq, CBS_ASN1_SEQUENCE)) Die("CBB resp seq");
    // responseStatus ENUMERATED successful(0)
    CBB status;
    if (!CBB_add_asn1(&seq, &status, CBS_ASN1_ENUMERATED)) Die("CBB status");
    if (!CBB_add_u8(&status, 0)) Die("CBB status val");
    // responseBytes [0] EXPLICIT
    CBB rb_outer;
    if (!CBB_add_asn1(&seq, &rb_outer,
                      CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0)) {
      Die("CBB rb outer");
    }
    CBB rb;
    if (!CBB_add_asn1(&rb_outer, &rb, CBS_ASN1_SEQUENCE)) Die("CBB rb seq");
    // responseType OID (id-pkix-ocsp-basic)
    CBB oid_cbb;
    if (!CBB_add_asn1(&rb, &oid_cbb, CBS_ASN1_OBJECT)) Die("CBB oid");
    if (!CBB_add_bytes(&oid_cbb, kOcspBasicOidBytes, sizeof(kOcspBasicOidBytes))) {
      Die("CBB oid bytes");
    }
    // response OCTET STRING (DER of BasicOCSPResponse)
    CBB basic_os;
    if (!CBB_add_asn1(&rb, &basic_os, CBS_ASN1_OCTETSTRING)) Die("CBB basic os");
    if (!CBB_add_bytes(&basic_os, basic.data(), basic.size())) Die("CBB basic data");
  }
  return CbbFinish(&resp_cbb);
}

} // namespace

// ---------------------------------------------------------------------------
// Main: generate all integration test certificates
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <output_dir>\n", argv[0]);
    return 1;
  }
  const std::string dir(argv[1]);

  // -----------------------------------------------------------------------
  // Root CA  (RSA 2048, self-signed)
  // -----------------------------------------------------------------------
  auto ca_key = MakeRSAKey();
  auto ca_cert = MakeCert(ca_key.get(), nullptr, nullptr, {
      .cn = "Test CA",
      .is_ca = true,
      .key_usage = "critical,cRLSign,keyCertSign",
  });
  WriteFile(P(dir, "cakey.pem"), PemKey(ca_key.get()));
  WriteFile(P(dir, "cacert.pem"), PemCert(ca_cert.get()));
  WriteInfoHeader(P(dir, "cacert_info.h"), "TEST_CA", ca_cert.get());

  // -----------------------------------------------------------------------
  // Intermediate CA  (RSA 2048, signed by root CA, pathlen:1)
  // -----------------------------------------------------------------------
  auto int_ca_key = MakeRSAKey();
  auto int_ca_cert = MakeCert(int_ca_key.get(), ca_cert.get(), ca_key.get(), {
      .cn = "Test Intermediate CA",
      .is_ca = true,
      .pathlen = 1,
      .key_usage = "critical,cRLSign,keyCertSign",
  });
  WriteFile(P(dir, "intermediate_cakey.pem"), PemKey(int_ca_key.get()));
  WriteFile(P(dir, "intermediate_cacert.pem"), PemCert(int_ca_cert.get()));
  WriteInfoHeader(P(dir, "intermediate_cacert_info.h"), "TEST_INTERMEDIATE_CA",
                  int_ca_cert.get());

  // -----------------------------------------------------------------------
  // Intermediate CA 2  (RSA 2048, signed by intermediate CA, pathlen:0)
  // -----------------------------------------------------------------------
  auto int_ca2_key = MakeRSAKey();
  auto int_ca2_cert =
      MakeCert(int_ca2_key.get(), int_ca_cert.get(), int_ca_key.get(), {
          .cn = "Test Intermediate CA 2",
          .is_ca = true,
          .pathlen = 0,
          .key_usage = "critical,cRLSign,keyCertSign",
      });
  WriteFile(P(dir, "intermediate_ca_2key.pem"), PemKey(int_ca2_key.get()));
  WriteFile(P(dir, "intermediate_ca_2cert.pem"), PemCert(int_ca2_cert.get()));
  WriteInfoHeader(P(dir, "intermediate_ca_2cert_info.h"), "TEST_INTERMEDIATE_CA_2",
                  int_ca2_cert.get());

  // chain files
  WriteFile(P(dir, "intermediate_ca_cert_chain.pem"),
            PemCert(ca_cert.get()) + PemCert(int_ca_cert.get()) +
                PemCert(int_ca2_cert.get()));
  WriteFile(P(dir, "intermediate_partial_ca_cert_chain.pem"),
            PemCert(int_ca_cert.get()) + PemCert(int_ca2_cert.get()));

  // -----------------------------------------------------------------------
  // Upstream CA  (RSA 2048, independent self-signed CA)
  // -----------------------------------------------------------------------
  auto upstream_ca_key = MakeRSAKey();
  auto upstream_ca_cert = MakeCert(upstream_ca_key.get(), nullptr, nullptr, {
      .cn = "Test Upstream CA",
      .is_ca = true,
      .key_usage = "critical,cRLSign,keyCertSign",
  });
  WriteFile(P(dir, "upstreamcakey.pem"), PemKey(upstream_ca_key.get()));
  WriteFile(P(dir, "upstreamcacert.pem"), PemCert(upstream_ca_cert.get()));
  WriteInfoHeader(P(dir, "upstreamcacert_info.h"), "TEST_UPSTREAMCA",
                  upstream_ca_cert.get());

  // -----------------------------------------------------------------------
  // Server cert  (RSA 2048, signed by root CA)
  // -----------------------------------------------------------------------
  auto server_key = MakeRSAKey();
  auto server_cert = MakeCert(server_key.get(), ca_cert.get(), ca_key.get(), {
      .cn = "Test Server",
      .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
      .ext_key_usage = "clientAuth,serverAuth",
      .san = "DNS:server1.example.com",
  });
  WriteFile(P(dir, "serverkey.pem"), PemKey(server_key.get()));
  WriteFile(P(dir, "servercert.pem"), PemCert(server_cert.get()));
  WriteInfoHeader(P(dir, "servercert_info.h"), "TEST_SERVER", server_cert.get());
  WriteHashHeader(P(dir, "servercert_hash.h"), "TEST_SERVER", server_cert.get());
  WriteDer(P(dir, "server_ocsp_resp.der"),
           MakeOcspResponse(server_cert.get(), ca_cert.get(), ca_key.get()));

  // -----------------------------------------------------------------------
  // Server2 cert  (RSA 2048, signed by root CA, multi-SAN)
  // -----------------------------------------------------------------------
  auto server2_key = MakeRSAKey();
  auto server2_cert = MakeCert(server2_key.get(), ca_cert.get(), ca_key.get(), {
      .cn = "Test Backend Team",
      .email = "backend-team@lyft.com",
      .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
      .ext_key_usage = "clientAuth,serverAuth",
      .san = "URI:spiffe://lyft.com/backend-team,URI:http://backend.lyft.com,"
             "DNS:lyft2.com,DNS:www.lyft2.com",
  });
  WriteFile(P(dir, "server2key.pem"), PemKey(server2_key.get()));
  WriteFile(P(dir, "server2cert.pem"), PemCert(server2_cert.get()));
  WriteInfoHeader(P(dir, "server2cert_info.h"), "TEST_SERVER2", server2_cert.get());
  WriteHashHeader(P(dir, "server2cert_hash.h"), "TEST_SERVER2", server2_cert.get());

  // -----------------------------------------------------------------------
  // Server ECDSA P-256
  // -----------------------------------------------------------------------
  auto server_ecdsa_key = MakeECKey(NID_X9_62_prime256v1);
  auto server_ecdsa_cert = MakeCert(server_ecdsa_key.get(), ca_cert.get(), ca_key.get(), {
      .cn = "Test Server",
      .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
      .ext_key_usage = "clientAuth,serverAuth",
      .san = "DNS:server1.example.com",
  });
  WriteFile(P(dir, "server_ecdsakey.pem"), PemKey(server_ecdsa_key.get()));
  WriteFile(P(dir, "server_ecdsacert.pem"), PemCert(server_ecdsa_cert.get()));
  WriteHashHeader(P(dir, "server_ecdsacert_hash.h"), "TEST_SERVER_ECDSA",
                  server_ecdsa_cert.get());
  WriteDer(P(dir, "server_ecdsa_ocsp_resp.der"),
           MakeOcspResponse(server_ecdsa_cert.get(), ca_cert.get(), ca_key.get()));

  // -----------------------------------------------------------------------
  // Server ECDSA P-384
  // -----------------------------------------------------------------------
  auto server_ecdsa_p384_key = MakeECKey(NID_secp384r1);
  auto server_ecdsa_p384_cert =
      MakeCert(server_ecdsa_p384_key.get(), ca_cert.get(), ca_key.get(), {
          .cn = "Test Server",
          .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
          .ext_key_usage = "clientAuth,serverAuth",
          .san = "DNS:server1.example.com",
      });
  WriteFile(P(dir, "server_ecdsa_p384key.pem"), PemKey(server_ecdsa_p384_key.get()));
  WriteFile(P(dir, "server_ecdsa_p384cert.pem"), PemCert(server_ecdsa_p384_cert.get()));
  WriteHashHeader(P(dir, "server_ecdsa_p384cert_hash.h"), "TEST_SERVER_ECDSA_P384",
                  server_ecdsa_p384_cert.get());
  WriteDer(P(dir, "server_ecdsa_p384_ocsp_resp.der"),
           MakeOcspResponse(server_ecdsa_p384_cert.get(), ca_cert.get(), ca_key.get()));

  // -----------------------------------------------------------------------
  // Server ECDSA P-521
  // -----------------------------------------------------------------------
  auto server_ecdsa_p521_key = MakeECKey(NID_secp521r1);
  auto server_ecdsa_p521_cert =
      MakeCert(server_ecdsa_p521_key.get(), ca_cert.get(), ca_key.get(), {
          .cn = "Test Server",
          .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
          .ext_key_usage = "clientAuth,serverAuth",
          .san = "DNS:server1.example.com",
      });
  WriteFile(P(dir, "server_ecdsa_p521key.pem"), PemKey(server_ecdsa_p521_key.get()));
  WriteFile(P(dir, "server_ecdsa_p521cert.pem"), PemCert(server_ecdsa_p521_cert.get()));
  WriteHashHeader(P(dir, "server_ecdsa_p521cert_hash.h"), "TEST_SERVER_ECDSA_P521",
                  server_ecdsa_p521_cert.get());
  WriteDer(P(dir, "server_ecdsa_p521_ocsp_resp.der"),
           MakeOcspResponse(server_ecdsa_p521_cert.get(), ca_cert.get(), ca_key.get()));

  // -----------------------------------------------------------------------
  // Long server cert  (RSA 2048, extra SANs for compression/large-cert tests)
  // -----------------------------------------------------------------------
  auto long_server_key = MakeRSAKey();
  auto long_server_cert = MakeCert(long_server_key.get(), ca_cert.get(), ca_key.get(), {
      .cn = "Test Backend Team",
      .email = "backend-team@lyft.com",
      .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
      .ext_key_usage = "clientAuth,serverAuth",
      .san = "URI:spiffe://lyft.com/backend-team,URI:http://backend.lyft.com,"
             "DNS:lyft.com,DNS:www.lyft.com",
  });
  WriteFile(P(dir, "long_serverkey.pem"), PemKey(long_server_key.get()));
  WriteFile(P(dir, "long_servercert.pem"), PemCert(long_server_cert.get()));
  WriteInfoHeader(P(dir, "long_servercert_info.h"), "TEST_LONG_SERVER", long_server_cert.get());
  WriteHashHeader(P(dir, "long_servercert_hash.h"), "TEST_LONG_SERVER", long_server_cert.get());
  WriteDer(P(dir, "long_server_ocsp_resp.der"),
           MakeOcspResponse(long_server_cert.get(), ca_cert.get(), ca_key.get()));

  // -----------------------------------------------------------------------
  // Client cert  (RSA 2048, signed by root CA)
  // -----------------------------------------------------------------------
  auto client_key = MakeRSAKey();
  auto client_cert = MakeCert(client_key.get(), ca_cert.get(), ca_key.get(), {
      .cn = "Test Frontend Team",
      .email = "frontend-team@lyft.com",
      .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
      .ext_key_usage = "clientAuth,serverAuth",
      .san = "URI:spiffe://lyft.com/frontend-team,URI:http://frontend.lyft.com,"
             "DNS:lyft.com,DNS:www.lyft.com,IP:1.2.3.4,IP:0:1:2:3::4",
  });
  WriteFile(P(dir, "clientkey.pem"), PemKey(client_key.get()));
  WriteFile(P(dir, "clientcert.pem"), PemCert(client_cert.get()));
  WriteHashHeader(P(dir, "clientcert_hash.h"), "TEST_CLIENT", client_cert.get());

  // -----------------------------------------------------------------------
  // Client2 cert  (RSA 2048, signed by intermediate CA 2)
  // -----------------------------------------------------------------------
  auto client2_key = MakeRSAKey();
  auto client2_cert =
      MakeCert(client2_key.get(), int_ca2_cert.get(), int_ca2_key.get(), {
          .cn = "Test Frontend Team 2",
          .email = "frontend-team@lyft.com",
          .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
          .ext_key_usage = "clientAuth,serverAuth",
          .san = "URI:spiffe://lyft.com/frontend-team,DNS:lyft.com,DNS:www.lyft.com",
      });
  WriteFile(P(dir, "client2key.pem"), PemKey(client2_key.get()));
  WriteFile(P(dir, "client2cert.pem"), PemCert(client2_cert.get()));
  WriteHashHeader(P(dir, "client2cert_hash.h"), "TEST_CLIENT2", client2_cert.get());
  // client2 full chain: leaf + int_ca_2 + int_ca + root_ca
  WriteFile(P(dir, "client2_chain.pem"),
            PemCert(client2_cert.get()) + PemCert(int_ca2_cert.get()) +
                PemCert(int_ca_cert.get()) + PemCert(ca_cert.get()));

  // -----------------------------------------------------------------------
  // Client ECDSA P-256  (signed by root CA)
  // -----------------------------------------------------------------------
  auto client_ecdsa_key = MakeECKey(NID_X9_62_prime256v1);
  auto client_ecdsa_cert =
      MakeCert(client_ecdsa_key.get(), ca_cert.get(), ca_key.get(), {
          .cn = "Test Frontend Team",
          .email = "frontend-team@lyft.com",
          .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
          .ext_key_usage = "clientAuth,serverAuth",
          .san = "URI:spiffe://lyft.com/frontend-team,URI:http://frontend.lyft.com,"
                 "DNS:lyft.com,DNS:www.lyft.com,IP:1.2.3.4,IP:0:1:2:3::4",
      });
  WriteFile(P(dir, "client_ecdsakey.pem"), PemKey(client_ecdsa_key.get()));
  WriteFile(P(dir, "client_ecdsacert.pem"), PemCert(client_ecdsa_cert.get()));
  WriteHashHeader(P(dir, "client_ecdsacert_hash.h"), "TEST_CLIENT_ECDSA",
                  client_ecdsa_cert.get());

  // -----------------------------------------------------------------------
  // Upstream server cert  (RSA 2048, signed by upstream CA)
  // -----------------------------------------------------------------------
  auto upstream_key = MakeRSAKey();
  auto upstream_cert =
      MakeCert(upstream_key.get(), upstream_ca_cert.get(), upstream_ca_key.get(), {
          .cn = "Test Upstream Server",
          .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
          .ext_key_usage = "clientAuth,serverAuth",
          .san = "DNS:*.lyft.com,IP:127.0.0.1,IP:::1",
      });
  WriteFile(P(dir, "upstreamkey.pem"), PemKey(upstream_key.get()));
  WriteFile(P(dir, "upstreamcert.pem"), PemCert(upstream_cert.get()));
  WriteHashHeader(P(dir, "upstreamcert_hash.h"), "TEST_UPSTREAM", upstream_cert.get());

  // -----------------------------------------------------------------------
  // Upstream localhost cert  (RSA 2048, signed by upstream CA)
  // -----------------------------------------------------------------------
  auto upstream_localhost_key = MakeRSAKey();
  auto upstream_localhost_cert =
      MakeCert(upstream_localhost_key.get(), upstream_ca_cert.get(), upstream_ca_key.get(), {
          .cn = "Test Upstream Server",
          .key_usage = "nonRepudiation,digitalSignature,keyEncipherment",
          .ext_key_usage = "clientAuth,serverAuth",
          .san = "DNS:localhost,IP:127.0.0.1,IP:::1",
      });
  WriteFile(P(dir, "upstreamlocalhostkey.pem"), PemKey(upstream_localhost_key.get()));
  WriteFile(P(dir, "upstreamlocalhostcert.pem"), PemCert(upstream_localhost_cert.get()));
  WriteHashHeader(P(dir, "upstreamlocalhostcert_hash.h"), "TEST_UPSTREAM_LOCALHOST",
                  upstream_localhost_cert.get());

  fprintf(stderr, "Generated %zu test certificates in %s/\n", g_serial - 1, dir.c_str());
  return 0;
}
