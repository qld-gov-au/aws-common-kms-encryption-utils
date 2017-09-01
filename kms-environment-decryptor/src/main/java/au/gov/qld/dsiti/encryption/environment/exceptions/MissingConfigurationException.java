package au.gov.qld.dsiti.encryption.environment.exceptions;

/**
 * Created by jeremy on 1/9/17.
 */
public class MissingConfigurationException extends RuntimeException {

    private String missingConfiguration;

    public MissingConfigurationException(String missingConfiguration) {
        super("Missing Configuration for '" + missingConfiguration + "'");
        this.missingConfiguration = missingConfiguration;
    }

    public String getMissingConfiguration() {
        return missingConfiguration;
    }
}
