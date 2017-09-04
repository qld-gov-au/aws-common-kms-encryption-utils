package au.gov.qld.dsiti.encryption.encryptors;

import au.gov.qld.dsiti.encryption.exceptions.EncryptionException;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by jeremy on 28/3/17.
 */
public class TestAESEncryptorWrapper {


    private AESEncryptorWrapper aesEncryptorWrapper = new AESEncryptorWrapper();

    private Key testKey;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void init() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        testKey = keyGen.generateKey();
    }


    @Test
    public void testEncryptDecryptWrapper_Success() {
        byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.encrypt(testKey, plainTextBytes, nonSecretData);
        
        byte[] generatedPrefix = Arrays.copyOfRange(encrypted, 0, 4);
        byte[] expectedPrefix = aesEncryptorWrapper.padHeader("G1".getBytes(StandardCharsets.UTF_8));
        assertTrue(Arrays.equals(expectedPrefix, generatedPrefix));

        byte[] decrypted = aesEncryptorWrapper.decrypt(testKey, encrypted, nonSecretData);
        assertTrue(Arrays.equals(plainTextBytes, decrypted));
    }

    @Test
    public void testEncryptDecryptWrapper_EmptyContent_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Invalid Input for Encryption"));

        //byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.encrypt(testKey, null, nonSecretData);
    }

    @Test
    public void testEncryptDecryptWrapper_EmptyParams_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Encryption Exception"));

        //byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.encrypt(null, null, null);
    }

    @Test
    public void testEncryptDecryptWrapper_InvalidContent_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Unable to decrypt input"));

        //byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.decrypt(testKey, "plaintext".getBytes(StandardCharsets.UTF_8), nonSecretData);
    }

    @Test
    public void testEncryptDecryptWrapper_NullParams_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Unable to decrypt input"));

        //byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.decrypt(null, null, null);
    }

    @Test
    public void testEncryptDecryptWrapper_InvalidContentCorrectPrefix_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Invalid Input for Encryption"));

        byte[] expectedPrefix = aesEncryptorWrapper.padHeader("G1".getBytes(StandardCharsets.UTF_8));

        //byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.decrypt(testKey, ArrayUtils.addAll(expectedPrefix, "plaintext".getBytes(StandardCharsets.UTF_8)), nonSecretData);
    }

    @Test
    public void testEncryptDecryptWrapper_InvalidPrefix_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Unable to decrypt input"));

        byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.encrypt(testKey, plainTextBytes, nonSecretData);
        encrypted[0]++;
        byte[] decrypted = aesEncryptorWrapper.decrypt(testKey, encrypted, nonSecretData);
    }

    @Test
    public void testEncryptDecryptWrapper_IncorrectNonSecretData_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Unable to decrypt input"));

        byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] incorrectNonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.encrypt(testKey, plainTextBytes, nonSecretData);
        encrypted[0]++;
        byte[] decrypted = aesEncryptorWrapper.decrypt(testKey, encrypted, incorrectNonSecretData);
    }

    @Test
    public void testEncryptDecryptWrapper_NullNonSecretData_ThrowsException() {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Unable to decrypt input"));

        byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] incorrectNonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = aesEncryptorWrapper.encrypt(testKey, plainTextBytes, nonSecretData);
        encrypted[0]++;
        byte[] decrypted = aesEncryptorWrapper.decrypt(testKey, encrypted, null);
    }

    @Test
    public void testPadHeaderMaxLengthOf4() {
       byte[] expectedPrefix = aesEncryptorWrapper.padHeader(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
       assertEquals(4, expectedPrefix.length);
    }
}
