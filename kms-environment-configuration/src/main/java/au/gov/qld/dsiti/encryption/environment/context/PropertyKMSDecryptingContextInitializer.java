package au.gov.qld.dsiti.encryption.environment.context;

import au.gov.qld.dsiti.encryption.environment.ConfigurationDecryptor;
import au.gov.qld.dsiti.encryption.environment.kms.KmsConfigurationDecryptor;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.*;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This ContextInitializer will process any properties that require Decrypting with KMS.
 *
 * (based off discussion on: https://stackoverflow.com/questions/31989883/process-spring-boot-externalized-property-values)
 *
 * Property value must be something like:
 *
 * sensitive.password=kms(AQICAHhttNV4IbOS8nYKtNRgmeyS/LbslpW/5hmUTWq...)
 *
 * Requirements:
 *
 * 1. 'kms.region' must exist, otherwise 'ap-southeast-2' will be used.
 *
 * Usage in SpringBoot:

 public static void main(String[] args) {
     LOG.info("Starting CIDM Neo application");
     SpringApplication application=new SpringApplication(NeoApplication.class);
     application.addInitializers(new PropertyKMSDecryptingContextInitializer());
     application.run(args);
     SpringApplication.run(NeoApplication.class, args);
 }

 @Override
 protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
     application.initializers(new PropertyKMSDecryptingContextInitializer());
     return application.sources(NeoApplication.class);
 }

 *
 */
public class PropertyKMSDecryptingContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private static final Pattern decodePasswordPattern = Pattern.compile("kms\\((.*?)\\)");

    private ConfigurationDecryptor configurationDecryptor;

    private String kmsRegion;

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ConfigurableEnvironment environment = applicationContext.getEnvironment();
        kmsRegion = environment.getProperty("kms.region");

        for (PropertySource<?> propertySource : environment.getPropertySources()) {
            Map<String, Object> propertyOverrides = new LinkedHashMap<>();
            decryptKMSPasswords(environment, propertySource, propertyOverrides);
            if (!propertyOverrides.isEmpty()) {
                PropertySource<?> decodedProperties = new MapPropertySource("decoded "+ propertySource.getName(), propertyOverrides);
                environment.getPropertySources().addBefore(propertySource.getName(), decodedProperties);
            }
        }
    }


    /**
     * decrypt ALL KMS Passwords from any property source.
     *
     * @param environment ConfigurableEnvironment
     * @param source PropertySource
     * @param propertyOverrides  Map of all property overrides (i.e. decrypted property values)
     */
    private void decryptKMSPasswords(ConfigurableEnvironment environment, PropertySource<?> source, Map<String, Object> propertyOverrides) {
        if (source instanceof EnumerablePropertySource) {
            EnumerablePropertySource<?> enumerablePropertySource = (EnumerablePropertySource<?>) source;
            for (String key : enumerablePropertySource.getPropertyNames()) {
                //use the environment.getProperty(key) as this will resolve the property if it's using an environment variable
                String rawValue = environment.getProperty(key);
                String decodedValue = decryptPasswordsInString(rawValue);
                propertyOverrides.put(key, decodedValue);
            }
        }
    }

    /**
     * Decrypts any kms encrypted passwords.
     *
     * @param input Property Value
     * @return override/decrypted value.
     */
    private String decryptPasswordsInString(String input) {
        if (input == null) return null;
        StringBuffer output = new StringBuffer();
        Matcher matcher = decodePasswordPattern.matcher(input);
        while (matcher.find()) {
            String replacement = getConfigurationDecryptor().decrypt(matcher.group(1));
            matcher.appendReplacement(output, replacement);
        }
        matcher.appendTail(output);
        return output.toString();
    }

    /**
     * Constructs a new ConfigurationDecryptor using the specified KMS Region
     * @return ConfigurationDecryptor
     */
    private ConfigurationDecryptor getConfigurationDecryptor() {
        if (configurationDecryptor == null) {
            AWSKMS kmsClient = AWSKMSClientBuilder.standard().withRegion(kmsRegion).build();
            configurationDecryptor = new KmsConfigurationDecryptor(kmsClient);
        }
        return configurationDecryptor;
    }

}
