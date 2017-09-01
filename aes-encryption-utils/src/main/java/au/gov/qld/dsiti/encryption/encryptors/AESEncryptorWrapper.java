package au.gov.qld.dsiti.encryption.encryptors;

import au.gov.qld.dsiti.encryption.exceptions.EncryptionException;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;


/**
 * AES Encryption Wrapper.
 *
 * Aims:
 * 1. Should abstract the consumer away from specific encryption implementation.
 * 2. Should allow for the encryption implementation to be updated at a later time and still decrypt.
 */
public final class AESEncryptorWrapper {

    private static final Logger LOG = LoggerFactory.getLogger(AESEncryptorWrapper.class);

    private final AESEncryptor defaultEncryptor = new AESGCMEncryptor();
    private final AESEncryptor[] availableEncryptors = new AESEncryptor[]{new AESGCMEncryptor()};

    /**
     * Each encrypted value will be have a prefix added that identifies which AESEncryptor created the encrypted content.
     * The Version returned from the AESEncryptor will be padded to the following length.
     */
    private static int versionPaddingLength = 4;

    /**
     * Encrypts data
     *
     * @param key - Secret Key used for Encryption
     * @param toEncrypt - byte[] data to Encrypt
     * @param nonSecretData - additional data passed in for verification
     * @return encrypted data with prefix
     * @throws EncryptionException - thrown for any crypto exceptions
     */
    public byte[] encrypt(final Key key, byte[] toEncrypt, byte[] nonSecretData) {
        byte[] headerPrefix = padHeader(defaultEncryptor.getVersion());
        byte[] encryptedContent = defaultEncryptor.encrypt(key, toEncrypt, nonSecretData);
        return ArrayUtils.addAll(headerPrefix, encryptedContent);
    }

    /**
     * Decrypts data
     *
     * @param key - Secret Key used for Encryption
     * @param toDecrypt - byte[] data to Decrypt (must include prefix)
     * @param nonSecretData - additional data passed in for verification
     * @return decrypted data
     * @throws EncryptionException - thrown for any crypto exceptions
     */
    public byte[] decrypt(final Key key, byte[] toDecrypt, byte[] nonSecretData) {
        //extract header from content
        byte[] headerPrefix = ArrayUtils.subarray(toDecrypt, 0, versionPaddingLength);
        for (AESEncryptor aesEncryptor: availableEncryptors) {
            //compare with expected header
            byte[] encryptorHeader = padHeader(aesEncryptor.getVersion());
            if (Arrays.equals(headerPrefix, encryptorHeader)) {
                //decrypt
                byte[] encryptedContent =  ArrayUtils.subarray(toDecrypt, versionPaddingLength, toDecrypt.length);
                return aesEncryptor.decrypt(key, encryptedContent, nonSecretData);
            }
        }
        LOG.error("Unsupported Encryption prefix: {}", new String(nonSecretData, StandardCharsets.UTF_8));
        throw new EncryptionException("Unable to decrypt input");
    }

    /**
     * Pads the given version into a new array with a length of 4
     * @param version - AESEncryptor version value
     * @return byte[] with length of 4
     */
    byte[] padHeader(byte[] version) {
        return Arrays.copyOf(version, versionPaddingLength);
    }



}
