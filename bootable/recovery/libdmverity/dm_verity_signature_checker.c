#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/rsa.h>

#include <pub_certs.h>

#define	MAX_CERT_SIZE	2048
//uint8_t	samsung_root_cert[MAX_CERT_SIZE];
uint32_t	samsung_root_cert_size = sizeof(samsung_root_cert);
uint8_t	ca_cert[MAX_CERT_SIZE];
uint32_t	ca_cert_size;
uint8_t	sign_cert[MAX_CERT_SIZE];
uint32_t	sign_cert_size;

#define	SIGN_SIZE	256
uint8_t	*data;
uint32_t	data_len;
#define	HASH_SIZE	32 /* SHA256 */
#define	SHA1_SIZE	20 /* SHA1 */

uint8_t	hash[HASH_SIZE];

uint8_t	*blob;
uint32_t	blob_len;

uint8_t	signature[SIGN_SIZE];

int calc_hash_sha256()
{
	/* data, data_len and hash should be populated */
	int ret;
	SHA256_CTX	ctx;

	ret = SHA256_Init(&ctx);
	if (0 == ret) {
		fprintf(stderr, "Error initing sha256 hash\n");
		return -1;
	}

	ret = SHA256_Update(&ctx, data, data_len);
	if (0 == ret) {
		fprintf(stderr, "Error updating sha has\n");
		return -1;
	}

	ret = SHA256_Final(hash, &ctx);
	if (0 == ret) {
		fprintf(stderr, "Error finalizing hash\n");
		return -1;
	}
	return 0;
}

int calc_hash_sha1()
{
	/* data, data_len and hash should be populated */
	int ret;
	SHA_CTX	ctx;

	ret = SHA1_Init(&ctx);
	if (0 == ret) {
		fprintf(stderr, "Error initing sha1 hash\n");
		return -1;
	}

	ret = SHA1_Update(&ctx, data, data_len);
	if (0 == ret) {
		fprintf(stderr, "Error updating sha1 hash\n");
		return -1;
	}

	ret = SHA1_Final(hash, &ctx);
	if (0 == ret) {
		fprintf(stderr, "Error finalizing sha1 hash\n");
		return -1;
	}
	return 0;
}

static int cb(int ok, X509_STORE_CTX *ctx)
        {
        int cert_error = X509_STORE_CTX_get_error(ctx);
        X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
	X509 *current_issuer = X509_STORE_CTX_get0_current_issuer(ctx);

        if (!ok)
                {
                if (current_cert)
                        {
                        X509_NAME_print_ex_fp(stdout,
                                X509_get_subject_name(current_cert),
                                0, XN_FLAG_ONELINE);
                        printf("\n");
			if(current_issuer)
                        	X509_NAME_print_ex_fp(stdout,
                                	X509_get_subject_name(current_issuer),
	                                0, XN_FLAG_ONELINE);
        	                printf("\n"); 
                        }
                printf("%serror %d at %d depth lookup:%s\n",
                        X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path]" : "",
                        cert_error,
                        X509_STORE_CTX_get_error_depth(ctx),
                        X509_verify_cert_error_string(cert_error));
                switch(cert_error)
                        {
                        case X509_V_ERR_NO_EXPLICIT_POLICY:
                        case X509_V_ERR_CERT_HAS_EXPIRED:
			case X509_V_ERR_CERT_NOT_YET_VALID:

                        /* since we are just checking the certificates, it is
                         * ok if they are self signed. But we should still warn
                         * the user.
                         */

                        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                        /* Continue after extension errors too */
                        case X509_V_ERR_INVALID_CA:
                        case X509_V_ERR_INVALID_NON_CA:
                        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
                        case X509_V_ERR_INVALID_PURPOSE:
                        case X509_V_ERR_CRL_HAS_EXPIRED:
                        case X509_V_ERR_CRL_NOT_YET_VALID:
                        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:

                        ok = 1;

                        }

                return ok;

                }
        return(ok);
        }

int parse_blob()
{
	/* blob_len and blob need to be populated. It will give back signature
	 * and 2 certs
	 */
	uint32_t	index = 0, size;

	if (blob_len < SIGN_SIZE) {
		fprintf(stderr, "Malformed blob 1\n");
		return -1;
	}
	memcpy(signature, blob, SIGN_SIZE);
	index = SIGN_SIZE;

	size = blob[index++];
	size <<= 8;
	size += blob[index++];
	if (index + size > blob_len) {
		fprintf(stderr, "Malformed blob 2\n");
		return -1;
	}
	if(size > MAX_CERT_SIZE){/*boundary check*/
		fprintf(stderr,"ca_cert size exceeded MAX_CERT_SIZE.\n");
		return -1;
	}
	memcpy(ca_cert, blob + index, size);
	ca_cert_size = size;
	index += size;

	size = blob[index++];
	size <<= 8;
	size += blob[index++];
	if (index + size > blob_len) {
		fprintf(stderr, "Malformed blob 2\n");
		return -1;
	}
	
	if(size > MAX_CERT_SIZE){/*boundary check*/
		fprintf(stderr,"sign_cert size exceeded MAX_CERT_SIZE.\n");
		return -1;
	}	
	memcpy(sign_cert, blob + index, size);
	sign_cert_size = size;
	index += size;

	return 0;

}

int read_file_to_mem(char *path, uint8_t *buf, uint32_t buflen)
{
	struct stat l_stat;
	int ret, fd;

	ret = stat(path, &l_stat);
	if (0 != ret) {
		fprintf(stderr, "Failed to stat: %s\n", path);
		return -1;
	}

	if (buflen < l_stat.st_size) {
		fprintf(stderr, "Buffer length not enough to hold the file. Expected: %u\n", (unsigned int)l_stat.st_size);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open: %s\n", path);
		return -1;
	}

	ret = read(fd, buf, l_stat.st_size);
	if (ret != l_stat.st_size) {
		fprintf(stderr, "Failed to read : %d\n", ret);
		close(fd);
		return -1;
	}

	close(fd);
	return ret;
}

int read_verity_data()
{
	int ret;

	if(read(0, &data_len, sizeof(uint32_t)) != sizeof(uint32_t)) {
		fprintf(stderr, "Error reading data 1\n");
		return -1;
	}
	fprintf(stderr, "data_size: %d\n", data_len);
	data = malloc(data_len);
	if (data == NULL) {
		fprintf(stderr, "Error allocating memory for data\n");
		return -1;
	}

	if(read(0, data, data_len) != data_len) {
		fprintf(stderr, "Error reading data 2\n");
		return -1;
	}
	/* Remove trailing \0 from hash calculation. But do read it in */

	if(read(0, &blob_len, sizeof(uint32_t)) != sizeof(uint32_t)) {
		fprintf(stderr, "Error reading data 3\n");
		return -1;
	}
	fprintf(stderr, "blob_size: %d\n", blob_len);
	blob = malloc(blob_len);
	if (blob == NULL) {
		fprintf(stderr, "Error allocating memory for blob\n");
		return -1;
	}

	if(read(0, blob, blob_len) != blob_len) {
		fprintf(stderr, "Error reading data 4\n");
		return -1;
	}

	return 0;
}
static int do_sha1(uint8_t *src, uint32_t src_len, uint8_t *sha1_hash)
{
    /* data, data_len and hash should be populated */
    int ret;
    SHA_CTX ctx;

    ret = SHA1_Init(&ctx);
    if (0 == ret) {
        fprintf(stderr, "Error initing sha1 hash\n");
        return -1;
    }

    ret = SHA1_Update(&ctx, src, src_len);
    if (0 == ret) {
        fprintf(stderr, "Error updating sha1 hash\n");
        return -1;
    }

    ret = SHA1_Final(sha1_hash, &ctx);
    if (0 == ret) {
        fprintf(stderr, "Error finalizing sha1 hash\n");
        return -1;
    }
    return 0;
}
int verify_device_signature()
{
	int ret;
	X509_STORE *store;
	X509_STORE_CTX *ctx;
	X509 *cert, *X509_sign_cert, *X509_samsung_cert;
	EVP_PKEY *EVP_sign_key;
	EVP_MD_CTX *EVP_CTX_sign;
	EVP_PKEY_CTX *pctx;
	const EVP_MD	*md_type;
	RSA*	RSA_sign_key;
	uint8_t	*ptr;
	uint8_t sha1_hash_of_hash[SHA1_SIZE] = { 0 };

	ret = parse_blob();
	if (0 != ret) {
		fprintf(stderr, "Error parsing blob\n");
		return -1;
	}
/* =============================================================================================
 * Start of certificate chain verification
 * =============================================================================================
 */
	printf("Verifying certificate chain...");
	store = X509_STORE_new();

	ptr = samsung_root_cert;
	X509_samsung_cert = NULL;
	X509_samsung_cert = d2i_X509(NULL, (const unsigned char **)&ptr, samsung_root_cert_size);
	//X509_print_fp(stdout, X509_samsung_cert);
	if (NULL == X509_samsung_cert) {
		fprintf(stderr, "Error decoding samsung cert\n");
		return -1;
	}
	ret = X509_STORE_add_cert(store, X509_samsung_cert);
	if (0 == ret) {
		fprintf(stderr, "Failed to add cert %d\n", ret);

		return -1;
	}

	ptr = ca_cert;
	cert = NULL;
	cert = d2i_X509(NULL, (const unsigned char **)&ptr, ca_cert_size);
	//X509_print_fp(stdout, cert);
	if (cert == NULL) {
		fprintf(stderr, "Error decoding ca cert\n");
		
		return -1;
	}
	ret = X509_STORE_add_cert(store, cert);
	if (0 == ret) {
		fprintf(stderr, "Failed to add cert %d\n", ret);

		return -1;
	}

	ptr = sign_cert;
	X509_sign_cert = NULL;
	X509_sign_cert = d2i_X509(NULL, (const unsigned char **)&ptr, sign_cert_size);
	//X509_print_fp(stdout, X509_sign_cert);
	if (NULL == X509_sign_cert) {
		fprintf(stderr, "Error decoding sign cert\n");
		return -1;
	}

	ctx = X509_STORE_CTX_new();
	ret = X509_STORE_CTX_init(ctx, store, X509_sign_cert, NULL);
	if (0 == ret) {
		fprintf(stderr, "Error initing ctx\n");
		return -1;
	}

	/* For debugging */
	X509_STORE_CTX_set_verify_cb(ctx, cb);

	ret = X509_verify_cert(ctx);
	if (0 == ret) {
		ERR_print_errors_fp(stderr);
		ret = X509_STORE_CTX_get_error(ctx);
		fprintf(stderr, "Error verifying cert %d\n", ret);
		return 1;
	}
	printf("Success\n");

/* ==================================================================================
 * START OF SIGNATURE VERIFICATION 
 * ==================================================================================
 */
	printf("Verifying signature...");
	EVP_sign_key = X509_get_pubkey(X509_sign_cert);
	if (NULL == EVP_sign_key) {
		fprintf(stderr, "Error getting pubkey\n");
		return -1;
	}

	RSA_sign_key = EVP_PKEY_get1_RSA(EVP_sign_key);
	if (NULL == RSA_sign_key) {
		fprintf(stderr, "Error converting EVP to RSA key\n");
		return -1;
	}
	//RSA_print_fp(stdout, RSA_sign_key, 0);
	pctx = EVP_PKEY_CTX_new(EVP_sign_key, NULL);
	if(NULL == pctx) {
		fprintf(stderr, "Error getting EVP context\n");
		return -1;
	}

	ret = EVP_PKEY_verify_init(pctx);
	if (ret <= 0) {
		fprintf(stderr, "Verify init failed\n");
		return -1;
	}
#ifdef QSEE_TZ
	ret = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
#elif defined(EXYNOS_TZ)
	ret = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
#endif
	if (ret <= 0) {
		fprintf(stderr, "Error setting RSA padding\n");
		ERR_print_errors_fp(stderr);
		return -1;
	} 
	
#ifdef QSEE_TZ
	ret = EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256());
#elif defined(EXYNOS_TZ)
	ret = EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1());
#endif
	if (ret <= 0) {
		fprintf(stderr, "Error setting sig algo\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

#ifdef QSEE_TZ
	ret = EVP_PKEY_verify(pctx, signature, SIGN_SIZE, hash, HASH_SIZE);
#elif defined(EXYNOS_TZ)
	ret = do_sha1(hash, HASH_SIZE, sha1_hash_of_hash);
	if (ret < 0) {
		fprintf(stderr, "Error creating SHA1 digest of input hash\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}
	ret = EVP_PKEY_verify(pctx, signature, SIGN_SIZE, sha1_hash_of_hash, SHA1_SIZE);
#endif
	if (ret <= 0) {
		fprintf(stderr, "Error in sig verification\n");
		ERR_print_errors_fp(stderr);
		return 1;
	} else
		printf("Success\n");

	EVP_cleanup();

	return 0;
}

int verify_server_signature()
{
	EVP_PKEY *pub_key = NULL;
	RSA*	RSA_sign_key = NULL;
	EVP_PKEY_CTX *pctx;
	uint8_t	*key_ptr = tima_db_adonis_pub_key;
	int ret;

	pub_key = d2i_PUBKEY(NULL, &key_ptr, sizeof(tima_db_adonis_pub_key));
	if (!pub_key) {
		fprintf(stderr, "Error getting public key\n");
		return -1;
	}

	RSA_sign_key = EVP_PKEY_get1_RSA(pub_key);
	if (NULL == RSA_sign_key) {
		fprintf(stderr, "Error converting EVP to RSA key in server verification\n");
		return -1;
	}
	//RSA_print_fp(stdout, RSA_sign_key, 0);

	ret = RSA_public_decrypt(blob_len, blob, signature, RSA_sign_key, RSA_PKCS1_PADDING);
	if (ret <= 0) {
		fprintf(stderr, "Error in RSA decryption\n");
		return -1;
	}

	if (memcmp(hash, signature, SHA1_SIZE)) {
		fprintf(stderr, "Signature mismatch\n");
		return -1;
	}
	fprintf(stdout, "Success\n");

	EVP_cleanup();
	return 0;
}

int main()
{
	int ret;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

#if 0
	printf("Loading Samsung root cert...");
	samsung_root_cert_size = read_file_to_mem("Samsung.der", samsung_root_cert, MAX_CERT_SIZE);
	if (samsung_root_cert_size <= 0) {
		fprintf(stderr, "Failed to read file. Exiting %u %d\n", samsung_root_cert_size, samsung_root_cert_size);
		return -1;
	}
	printf("Success\n");

	printf("Loading dmverity CA cert...");
	ca_cert_size = read_file_to_mem("dmverity_root_crt", ca_cert, MAX_CERT_SIZE);
	if (ca_cert_size <= 0) {
		fprintf(stderr, "Failed to read file. Exiting %u %d\n", ca_cert_size, ca_cert_size);
		return -1;
	}
	printf("Success\n");

	printf("Loading dmverity signing cert...");
	sign_cert_size = read_file_to_mem("dmverity_ca_crt", sign_cert, MAX_CERT_SIZE);
	if (sign_cert_size <= 0) {
		fprintf(stderr, "Failed to read file. Exiting %u %d\n", sign_cert_size, sign_cert_size);
		return -1;
	}
	printf("Success\n");


	printf("Loading signature file...");
	ret = read_file_to_mem("dmverity_sig", signature, SIGN_SIZE);
	if (ret <= 0) {
		fprintf(stderr, "Failed to read file. Exiting 2\n");
		return -1;
	}
	printf("Success\n");
#endif

#if 0
	printf("Loading blob..");
	blob_len = read_file_to_mem("dmverity_all", blob, 4096);
	if ((int)blob_len <= 0) {
		fprintf(stderr, "Failed to read file. Exiting\n");
		return -1;
	}
	printf("Success\n");

	printf("Loading data file...");
	data_len = read_file_to_mem("dmverity_data", data, 1024);
	if (data_len <= 0) {
		fprintf(stderr, "Failed to read file. Exiting 1 \n");
		return -1;
	}
	printf("Success\n");
#endif

	ret = read_verity_data();
	if (0 != ret) {
		fprintf(stderr, "Error reading verity data from parent process\n");
		return -1;
	}

	if (blob_len == SIGN_SIZE) {
		/* Since blob is only RSA signature, this must be server-side signed */
		ret = calc_hash_sha1();
		if (0 != ret) {
			fprintf(stderr, "Error calculating hash\n");
			return -1;
		}
		return verify_server_signature();
	} else {
		/* Not RSA signature size. Try device signature */
		ret = calc_hash_sha256();
		if (0 != ret) {
			fprintf(stderr, "Error calculating hash\n");
			return -1;
		}
		return verify_device_signature();
	}

}
