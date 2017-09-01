package au.gov.qld.dsiti.encryption.environment;

/**
 * Created by jeremy on 1/9/17.
 */
public interface ApplicationEnvironmentConfiguration {

    /**
     * Signifies if this Environment Configuration value is Encrypted
     *
     * @return TRUE if it is encrypted, false otherwise
     */
    Boolean getEncrypted();

    /**
     * Environment key for this configuration
     *
     * @return String
     */
    String getEnvironmentKey();

}
