package au.gov.qld.dsiti.encryption.environment;

/**
 * Interface for decrypting configuration values
 */
public interface ConfigurationDecryptor {

    /**
     * Decrypts the Base64 encoded configuration alue.
     *
     * @param encryptedConfigurationValue - Must be Base64 Encoded
     * @return decrypted configuration value
     */
    String decrypt(String encryptedConfigurationValue);
}
