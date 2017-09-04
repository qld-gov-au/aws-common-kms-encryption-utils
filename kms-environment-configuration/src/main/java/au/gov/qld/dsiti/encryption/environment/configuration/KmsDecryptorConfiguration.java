package au.gov.qld.dsiti.encryption.environment.configuration;

import au.gov.qld.dsiti.encryption.environment.ConfigurationDecryptor;
import au.gov.qld.dsiti.encryption.environment.kms.KmsConfigurationDecryptor;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Configuration class to autowire a ConfigurationDecryptor based on the application.properties value 'aws.kms.enabled'.
 */
@Configuration
public class KmsDecryptorConfiguration {

    private final static Logger LOGGER = LoggerFactory.getLogger(KmsDecryptorConfiguration.class);

    @Configuration
    @ConditionalOnProperty(prefix = "aws.kms", name = "enabled", havingValue = "true", matchIfMissing = false)
    static class KmsTextEncryptorConfiguration {

        @Autowired
        private AWSKMS kms;

        @Bean
        ConfigurationDecryptor configurationDecryptor() {
            LOGGER.debug("Using KmsConfigurationDecryptor");
            return new KmsConfigurationDecryptor(kms);
        }
    }

    @Configuration
    @ConditionalOnProperty(prefix = "aws.kms", name = "enabled", havingValue = "false", matchIfMissing = true)
    static class NoopTextEncryptorConfiguration {

        @Bean
        ConfigurationDecryptor configurationDecryptor() {
            LOGGER.debug("Using NoopConfigurationDecryptor");
            return encryptedConfigurationValue -> encryptedConfigurationValue;
        }
    }

    @Configuration
    @ConditionalOnMissingBean(AWSKMS.class)
    static class KmsConfiguration {

        @Value("#{T(com.amazonaws.regions.Regions).fromName('${aws.region}')}")
        private Regions region;

        @Bean
        AWSKMS kms() {
            return AWSKMSClientBuilder.standard().withRegion(region).build();
        }

    }

}
