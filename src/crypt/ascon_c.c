#include "cose/crypto.h"
#include "cose/crypto/ascon_c.h"

static int ascon_aead_get_tag_size(cose_algo_t algo, uint16_t* t_bits, uint16_t* t_bytes) {
    switch (algo) {
        case COSE_ALGO_ASCON_AEAD128:
            *t_bits = 128;
            *t_bytes = 16;
            break;
        case COSE_ALGO_ASCON_AEAD128_64:
            *t_bits = 64;
            *t_bytes = 8;
            break;
        case COSE_ALGO_ASCON_AEAD128_32:
            *t_bits = 32;
            *t_bytes = 4;
            break;
        default:
            return -1;
    }

    return 0;
}

int cose_crypto_aead_encrypt_ascon(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo) {
    uint16_t t_bits, t_bytes;
    int res = ascon_aead_get_tag_size(algo, &t_bits, &t_bytes);
    if (res < 0) {
        return -1;
    }

    uint8_t* tag = c + msglen;
    res = ascon_aead_encrypt_trunc(
        tag,
        c,
        msg,
        msglen,
        aad,
        aadlen,
        npub,
        k,
        t_bits
    );
    if (res != 0) {
        return -1;
    }

    *clen = msglen + t_bytes;
    return 0;
}

int cose_crypto_aead_decrypt_ascon(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo) {
    uint16_t t_bits, t_bytes;
    int res = ascon_aead_get_tag_size(algo, &t_bits, &t_bytes);
    if (res < 0) {
        return -1;
    }

    const uint8_t* tag = c + clen - t_bytes;
    res = ascon_aead_decrypt_trunc(
        msg,
        tag,
        c,
        clen - t_bytes,
        aad,
        aadlen,
        npub,
        k,
        t_bits
    );
    if (res != 0) {
        return -1;
    }

    *msglen = clen - t_bytes;
    return 0;
}