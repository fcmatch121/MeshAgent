/* Core-trailer decryption hook support. Flag byte 0x01 in the top of the
   4-byte BE length marks an XOR-obfuscated core module. Key must match the
   server-side writer (MeshCentral fork). */
static const unsigned char obf_core_key[4] = { 0xA7, 0x31, 0xC4, 0x0E };
static void obf_core_decrypt(unsigned char *buf, unsigned int len)
{
	unsigned int i;
	for (i = 0; i < len; ++i) { buf[i] ^= (unsigned char)(obf_core_key[i & 3] ^ ((i * 31) & 0xFF)); }
}
#define OBF_CORE_FLAG_ENCRYPTED 0x01000000
