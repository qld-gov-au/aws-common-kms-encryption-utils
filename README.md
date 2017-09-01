# OSSSIO Encryption Helpers

This library contains modules that provide generic encryption functionality used accross multiple OSSSIO projects

## Development

Language: Java 8

Dependencies:
  * AWS KMS Sdk
  * Spring Boot Autoconfiguration/Context
  * Slf4j
  
## Modules

Current version:

```
<osssio.encryption.utils.version>1.0</osssio.encryption.utils.version>

```

### aes-encryption-utils

This library provides the AESGCMEncryptor methods.

```
<dependency>
     <groupId>au.gov.qld.dsiti</groupId>
     <artifactId>aes-encryption-utils</artifactId>
     <version>${osssio.encryption.utils.version}</version>
 </dependency>

```

### aes-encryption-utils

This library provides the ConfigurationDecryptor and KmsConfigurationDecryptor classes.

```
<dependency>
     <groupId>au.gov.qld.dsiti</groupId>
     <artifactId>kms-environment-decryptor</artifactId>
     <version>${osssio.encryption.utils.version}</version>
 </dependency>

```


### kms-environment-configuration

This library provides the KmsDecryptorConfiguration @Configuration class to autowire the ConfigurationDecryptor and KmsConfigurationDecryptor.

```
<dependency>
     <groupId>au.gov.qld.dsiti</groupId>
     <artifactId>kms-environment-configuration</artifactId>
     <version>${osssio.encryption.utils.version}</version>
 </dependency>

```

This Configuration requires the following application properies to be set:

```
aws.kms.enabled=true
aws.region=ap-southeast-2

```