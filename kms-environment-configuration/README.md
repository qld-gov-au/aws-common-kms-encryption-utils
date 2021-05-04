## kms-environment-configuration - For Spring Boot

This library provides the KmsDecryptorConfiguration @Configuration class to autowire the ConfigurationDecryptor and KmsConfigurationDecryptor.

Including this module dependency will automatically configure the above classes.

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


This is deprecated now that System Manager - Parameter Store is now available out of the box for 
boot property configuration.