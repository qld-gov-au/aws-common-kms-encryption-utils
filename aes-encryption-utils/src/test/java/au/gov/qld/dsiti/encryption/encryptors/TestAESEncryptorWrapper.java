package au.gov.qld.dsiti.encryption.encryptors;

import au.gov.qld.dsiti.encryption.exceptions.EncryptionException;
import org.apache.commons.lang3.RandomStringUtils;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.KeyGenerator;
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
    public void testPadHeaderMaxLengthOf4() {
       byte[] expectedPrefix = aesEncryptorWrapper.padHeader(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
       assertEquals(4, expectedPrefix.length);
    }
}
