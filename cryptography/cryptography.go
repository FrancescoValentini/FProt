// This package provides all the needed methods, constants and errors to work
// with cryptography
package cryptography

const AES_KEY_LENGTH = 32
const GCM_NONCE_LENGTH = 12 // 96-bit
const BUFFER_SIZE = 128     // KB
const GCM_TAG_SIZE = 16
const COUNTER_SIZE = 8   // 64-bit counter
const LEN_FIELD_SIZE = 4 // Ciphertext length field
const RANDOM_SIZE = 4    // 32-bit random part

// KDF Settings
const ARGON2ID_ITERATIONS = 10
const ARGON2ID_MEMORY = 128 * 1024
const ARGON2ID_THREADS = 4
const ARGON2ID_KEY_LENGTH = 32
