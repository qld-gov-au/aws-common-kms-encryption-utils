## aes-encryption-utils

This library provides the AESGCMEncryptor methods.

```
<dependency>
     <groupId>au.gov.qld.dsiti</groupId>
     <artifactId>aes-encryption-utils</artifactId>
     <version>${osssio.encryption.utils.version}</version>
 </dependency>

```

### Usage


```java

     private final AESEncryptorWrapper aesEncryptorFactory =  new AESEncryptorWrapper();



     private String encryptBytesBase64(String interactionId, Key key, byte[] bytesToEncrypt) {
         return Base64.encodeAsString(aesEncryptorFactory.encrypt(key, bytesToEncrypt, interactionId.getBytes(StandardCharsets.UTF_8)));
     }
 
     private byte[] decryptBase64Bytes(String interactionId, Key key, String base64ToDecrypt) {
         return aesEncryptorFactory.decrypt(key, Base64.decode(base64ToDecrypt), interactionId.getBytes(StandardCharsets.UTF_8));
     }


```

