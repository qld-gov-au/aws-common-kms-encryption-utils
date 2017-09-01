package au.gov.qld.dsiti.encryption.environment;

import au.gov.qld.dsiti.encryption.environment.exceptions.MissingConfigurationException;
import com.amazonaws.util.StringUtils;

/**
 * Loads the given ApplicationEnvironmentConfiguration from System.getenv() and decrypts with the given ConfigurationDecryptor if required.
 *
 */
public class EnvironmentConfigurationLoader {

    final private ConfigurationDecryptor configurationDecryptor;

    public EnvironmentConfigurationLoader(ConfigurationDecryptor configurationDecryptor) {
        this.configurationDecryptor = configurationDecryptor;
    }

    public String getValue(ApplicationEnvironmentConfiguration settings) {
         if (settings.getEncrypted()) {
             return getDecryptedValue(settings);
         }
         return getEnvironmentValue(settings.getEnvironmentKey());
    }

    String getDecryptedValue(ApplicationEnvironmentConfiguration settings) {
        return configurationDecryptor.decrypt(getEnvironmentValue(settings.getEnvironmentKey()));
    }

    private String getEnvironmentValue(String environmentKey) {
        String value = System.getenv(environmentKey);
        if (StringUtils.isNullOrEmpty(value)) {
            throw new MissingConfigurationException(environmentKey);
        }
        return value;
    }
}
