package au.gov.qld.dsiti.encryption.encryptors;

import java.security.Key;

/**
 * Interface for any AES Encryption implementation
 */
interface AESEncryptor {

    /**
     * Returns a version/identifier for this implementation.
     * Must be unique to all other configured AESEncryptors.
     * Must not be more than 4 bytes in length.
     * @return
     */
    byte[] getVersion();

    /**
     * Encrypts data
     *
     * @param key - Secret Key used for Encryption
     * @param toEncrypt - byte[] data to Encrypt
     * @param nonSecretData - additional data passed in for verification - must not be null
     * @return encrypted data
     */
    byte[] encrypt(final Key key, byte[] toEncrypt, byte[] nonSecretData);

    /**
     * Decrypts data
     *
     * @param key - Secret Key used for Encryption
     * @param toDecrypt - byte[] data to Decrypt
     * @param nonSecretData - additional data passed in for verification - must not be null
     * @return decrypted data
     */
    byte[] decrypt(final Key key, byte[] toDecrypt, byte[] nonSecretData);

}
