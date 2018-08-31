package au.gov.qld.dsiti.encryption.encryptors;

public interface AESPBKEncryptor {

    /**
     * Encrypts data
     *
     * Returns an encrypted byte[] with embedded: IV + SALT + TAG + DATA
     *
     * @param password - Shared Secret used for Encryption
     * @param toEncrypt - byte[] data to Encrypt
     * @return encrypted data
     */
    byte[] encrypt(final char[] password, byte[] toEncrypt);

    /**
     * Decrypts data
     *
     * Expects a byte[] with embedded: IV + SALT + TAG + DATA
     *
     * Will generally only be compatible with the output from the above encrypt method.
     *
     * @param password - Shared Secret used for Encryption
     * @param toDecrypt - byte[] data to Decrypt
     * @return decrypted data
     */
    byte[] decrypt(final char[] password, byte[] toDecrypt);

    /**
     * Encrypts data and returns the value HEX Encoded
     *
     * Returns an encrypted byte[] with embedded: IV + SALT + TAG + DATA
     *
     * @param password - Shared Secret used for Encryption
     * @param toEncrypt - byte[] data to Encrypt
     * @return encrypted data encoded in HEX
     */
    String encryptHex(final char[] password, byte[] toEncrypt);

    /**
     * Decrypts data provided HEX Encoded
     *
     * Expects the content to have embedded: IV + SALT + TAG + DATA
     *
     * Will generally only be compatible with the output from the above encrypt method.
     *
     * @param password - Shared Secret used for Encryption
     * @param hexToDecrypt - HEX encoded encrypted content
     * @return decrypted data
     */
    byte[] decryptHex(final char[] password, String hexToDecrypt);
}
