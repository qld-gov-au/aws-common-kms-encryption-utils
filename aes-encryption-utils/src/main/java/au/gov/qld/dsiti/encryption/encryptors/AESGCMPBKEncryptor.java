package au.gov.qld.dsiti.encryption.encryptors;

import au.gov.qld.dsiti.encryption.exceptions.EncryptionException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * This AES GCM Encrypt/Decrypt library matches exactly the routine used by the CIDM NEO Rules/Frontend code found:
 * https://servicesmadesimpler.govnet.qld.gov.au/bitbucket/projects/QGCIDM/repos/cidm-neo_frontend/browse/NeoLibraries/lib/encrypt.js
 * https://servicesmadesimpler.govnet.qld.gov.au/bitbucket/projects/QGCIDM/repos/cidm-neo_frontend/browse/NeoLibraries/lib/decrypt.js
 * https://servicesmadesimpler.govnet.qld.gov.au/bitbucket/projects/QGCIDM/repos/auth0-tenant/browse/idm/rules/46-save-the-qid.js
 *
 */
public class AESGCMPBKEncryptor implements AESPBKEncryptor {

    private static final Logger LOG = LoggerFactory.getLogger(AESGCMPBKEncryptor.class);

    private static final String INVALID_DECRYPTION_INPUT_EXCEPTION_MESSAGE = "Invalid Input for Decryption";
    private static final String GENERIC_ENCRYPTION_EXCEPTION_MESSAGE = "Encryption Exception";

    private static final int PBKDF2_ITERATIONS = 2145;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final String ENCRYPTION_ALGORITHM_NAME = "AES";

    private static final int SALT_LENGTH_BYTES = 64;
    private static final int IV_LENGTH_BYTES = 12;
    private static final int HASH_LENGTH_BYTES = 32;
    private static final int TAG_LENGTH_BYTES = 16;
    private static final int TAG_LENGTH_BITS = 16 * 8;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public byte[] encrypt(final char[] password, byte[] toEncrypt) {
        try {
            byte[] salt = generateSalt();
            byte[] iv = generateIV();

            // Compute the hash of the provided password, using the salt, iteration count, and hash length
            byte[] key = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
            SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM_NAME);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);

            //use the cipher to determine the output size
            byte[] encrypted = new byte[cipher.getOutputSize(toEncrypt.length)];
            int updateSize = cipher.update(toEncrypt, 0, toEncrypt.length, encrypted, 0);
            cipher.doFinal(encrypted, updateSize);

            //tag is last 16 bytes
            byte[] tag = new byte[TAG_LENGTH_BYTES];
            byte[] text = new byte[encrypted.length - TAG_LENGTH_BYTES];

            System.arraycopy(encrypted, encrypted.length - TAG_LENGTH_BYTES, tag, 0, TAG_LENGTH_BYTES);
            System.arraycopy(encrypted, 0, text, 0, encrypted.length - TAG_LENGTH_BYTES);

            byte[] message = new byte[SALT_LENGTH_BYTES + IV_LENGTH_BYTES + encrypted.length];

            //SALT + IV + TAG + TEXT
            System.arraycopy(salt, 0, message, 0, SALT_LENGTH_BYTES);
            System.arraycopy(iv, 0, message, SALT_LENGTH_BYTES, IV_LENGTH_BYTES);
            System.arraycopy(tag, 0, message, SALT_LENGTH_BYTES + IV_LENGTH_BYTES, tag.length);
            System.arraycopy(text, 0, message, SALT_LENGTH_BYTES + IV_LENGTH_BYTES + tag.length, text.length);

            return message;
        } catch(GeneralSecurityException gse) {
            LOG.error("Unable to perform Decryption: " + gse.getMessage(), gse);
            throw new EncryptionException(GENERIC_ENCRYPTION_EXCEPTION_MESSAGE, gse);
        }
    }

    @Override
    public byte[] decrypt(final char[] password, byte[] toDecrypt) {
        try {
            //The input to decrypt is made of the following components that need to be extract: SALT + IV + TAG + TEXT
            byte[] salt = ArrayUtils.subarray(toDecrypt, 0, SALT_LENGTH_BYTES);
            byte[] iv = ArrayUtils.subarray(toDecrypt, SALT_LENGTH_BYTES, SALT_LENGTH_BYTES + IV_LENGTH_BYTES);
            byte[] tag = ArrayUtils.subarray(toDecrypt, SALT_LENGTH_BYTES + IV_LENGTH_BYTES, SALT_LENGTH_BYTES + IV_LENGTH_BYTES + TAG_LENGTH_BYTES);
            byte[] text = ArrayUtils.subarray(toDecrypt, SALT_LENGTH_BYTES + IV_LENGTH_BYTES + TAG_LENGTH_BYTES, toDecrypt.length);

            byte[] textAndTag = new byte[text.length + tag.length];
            System.arraycopy(text, 0, textAndTag, 0, text.length);
            System.arraycopy(tag, 0, textAndTag, text.length, tag.length);

            // Compute the hash of the provided password, using the same salt,
            // iteration count, and hash length
            byte[] key = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
            SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM_NAME);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
            return cipher.doFinal(textAndTag);

        } catch(GeneralSecurityException gse) {
            LOG.error("Unable to perform Decryption: " + gse.getMessage(), gse);
            throw new EncryptionException(GENERIC_ENCRYPTION_EXCEPTION_MESSAGE, gse);
        }
    }

    @Override
    public String encryptHex(char[] password, byte[] toEncrypt) {
        return toHex(encrypt(password, toEncrypt));
    }

    @Override
    public byte[] decryptHex(char[] password, String hexToDecrypt) {
        try {
            byte[] toDecrypt = fromHex(hexToDecrypt);
            return decrypt(password, toDecrypt);
        } catch (DecoderException de) {
            LOG.warn("Received Invalid HEX Input: {}", de.getMessage());
           throw new EncryptionException(INVALID_DECRYPTION_INPUT_EXCEPTION_MESSAGE);
        }
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("ALGORITHM", ALGORITHM)
                .append("PBK", PBKDF2_ALGORITHM)
                .toString();
    }

    private byte[] generateIV() {
        return generateRandom(IV_LENGTH_BYTES);
    }

    private byte[] generateSalt() {
        return generateRandom(SALT_LENGTH_BYTES);
    }

    private byte[] generateRandom(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     *  Computes the PBKDF2 hash of a password.
     *
     * @param   password    the password to hash.
     * @param   salt        the salt
     * @param   iterations  the iteration count (slowness factor)
     * @param   bytes       the length of the hash to compute in bytes
     * @return              the PBDKF2 hash of the password
     */
    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }

    /**
     * Converts a string of hexadecimal characters into a byte array.
     *
     * @param   hex         the hex string
     * @return              the hex string decoded into a byte array
     */
    private static byte[] fromHex(String hex) throws DecoderException {
        return Hex.decodeHex(hex.toCharArray());
    }

    /**
     * Converts a byte array into a hexadecimal string.
     *
     * @param   array       the byte array to convert
     * @return              a length*2 character string encoding the byte array
     */
    private static String toHex(byte[] array) {
        return Hex.encodeHexString(array);
    }
}
