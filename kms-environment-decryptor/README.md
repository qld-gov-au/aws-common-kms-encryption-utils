## aes-encryption-utils

This library provides the ConfigurationDecryptor and KmsConfigurationDecryptor classes.

```
<dependency>
     <groupId>au.gov.qld.dsiti</groupId>
     <artifactId>kms-environment-decryptor</artifactId>
     <version>${osssio.encryption.utils.version}</version>
 </dependency>

```

### Usage


Example usage for a Java Spring application:

```java
    @Value("${psd.api.key}")
    private String psdApiKey;

    @Value("${av.api.key}")
    private String avApiKey;

    @Autowired
    private ConfigurationDecryptor configurationDecryptor;

    @PostConstruct
    public void decrypt() {
        psdApiKey = configurationDecryptor.decrypt(psdApiKey);
        avApiKey = configurationDecryptor.decrypt(avApiKey);
    }

```


Another Example usage for a Java Spring application using constructor injection:

```java
    private final String coaRequestURI;
    private final String coaAPIKey;

    @Autowired
    public CoaServiceImpl(@Value("${coa.api.url}") final String coaRequestURI,
                          @Value("${coa.api.key}") final String coaAPIKey,
                          ConfigurationDecryptor configurationDecryptor) {
        this.coaRequestURI = coaRequestURI;
        this.coaAPIKey = configurationDecryptor.decrypt(coaAPIKey);
    }

```


Example usage for a Java based Lambda function:

```java

enum Settings implements ApplicationEnvironmentConfiguration {

    SQS_URL("SqsUrl", false),
    
    KITEWORKS_CLIENT_ID("KiteworksClientId", true),
    
    SNOW_PASSWORD("ServiceNowPassword", true);

    private final String environmentKey;
    private final Boolean encrypted;

    Settings(String environmentKey, boolean encrypted) {
        this.environmentKey = environmentKey;
        this.encrypted = encrypted;
    }

    public Boolean getEncrypted() {
        return encrypted;
    }



    public String getEnvironmentKey() {
        return environmentKey;
    }
}


public class LambdaConfiguration {

    private final EnvironmentConfigurationLoader environmentConfigurationLoader;

    public LambdaConfiguration(EnvironmentConfigurationLoader environmentConfigurationLoader) {
        this.environmentConfigurationLoader = environmentConfigurationLoader;
    }

    public String getSqsUrl() {
         return environmentConfigurationLoader.getValue(Settings.SQS_URL);
    }

    
    public String getSnowPassword() {
        return environmentConfigurationLoader.getValue(Settings.SNOW_PASSWORD);
    }

    public String getKiteworksClientId() {
        return environmentConfigurationLoader.getValue(Settings.KITEWORKS_CLIENT_ID);
    }
    
}


```


