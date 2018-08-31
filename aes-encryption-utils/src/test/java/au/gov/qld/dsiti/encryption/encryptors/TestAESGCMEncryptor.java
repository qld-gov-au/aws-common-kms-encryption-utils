package au.gov.qld.dsiti.encryption.encryptors;

import au.gov.qld.dsiti.encryption.exceptions.EncryptionException;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by jeremy on 28/3/17.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({AESGCMEncryptor.class})
@PowerMockIgnore({"org.apache.http.conn.ssl.*", "javax.net.ssl.*" , "javax.crypto.*"})
public class TestAESGCMEncryptor {

    private static final Logger LOG = LoggerFactory.getLogger(TestAESGCMEncryptor.class);

    private Key testKey;

    @Before
    public void init() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        testKey = keyGen.generateKey();
    }
    
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testToString() {
        AESGCMEncryptor aesgcmEncryptor = new AESGCMEncryptor();
        assertTrue(aesgcmEncryptor.toString().contains("AES/GCM/NoPadding"));
    }

    @Test
    public void testAESGCMEncryptor_InvalidKey_ThrowsException() throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Encryption Exception"));

        AESGCMEncryptor aesgcmEncryptor = new AESGCMEncryptor();

        AESGCMEncryptor spy = PowerMockito.spy(aesgcmEncryptor);
        PowerMockito.when(spy.getCipherInstance()).thenThrow(new NoSuchAlgorithmException("error"));

        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = spy.encrypt(null, null, nonSecretData);
    }

    @Test
    public void testAESGCMEncryptor_EncryptGeneralEncryptionException_ThrowsException() throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException {
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Encryption Exception"));

        AESGCMEncryptor aesgcmEncryptor = new AESGCMEncryptor();

        AESGCMEncryptor spy = PowerMockito.spy(aesgcmEncryptor);
        PowerMockito.when(spy.getCipherInstance()).thenThrow(new NoSuchAlgorithmException("error"));

        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = spy.encrypt(testKey, null, nonSecretData);
    }

    @Test
    public void testAESGCMEncryptor_DecryptGeneralEncryptionException_ThrowsException() throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException {

        AESGCMEncryptor aesgcmEncryptor = new AESGCMEncryptor();

        AESGCMEncryptor spy = PowerMockito.spy(aesgcmEncryptor);

        byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = spy.encrypt(testKey, plainTextBytes, nonSecretData);

        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Encryption Exception"));

        PowerMockito.when(spy.getCipherInstance()).thenThrow(new NoSuchAlgorithmException("error"));
        byte[] decrypted = spy.decrypt(testKey, encrypted, nonSecretData);
    }

    @Test
    public void testAESGCMEncryptor_Decrypt_InvalidInput_GeneralEncryptionException_ThrowsException() throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException {

        AESGCMEncryptor aesgcmEncryptor = new AESGCMEncryptor();

        AESGCMEncryptor spy = PowerMockito.spy(aesgcmEncryptor);

        byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = spy.encrypt(testKey, plainTextBytes, nonSecretData);

        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Invalid Input for Encryption"));

        PowerMockito.when(spy.getCipherInstance()).thenThrow(new NoSuchAlgorithmException("error"));
        byte[] decrypted = spy.decrypt(testKey, ArrayUtils.subarray(encrypted, 0, 20), nonSecretData);
    }

    @Test
    public void testAESGCMEncryptor_Decrypt_InvalidNonSecretData_GeneralEncryptionException_ThrowsException() throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException {

        AESGCMEncryptor aesgcmEncryptor = new AESGCMEncryptor();

        AESGCMEncryptor spy = PowerMockito.spy(aesgcmEncryptor);

        byte[] plainTextBytes = RandomStringUtils.randomAscii(256).getBytes(StandardCharsets.UTF_8);
        byte[] nonSecretData = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = spy.encrypt(testKey, plainTextBytes, nonSecretData);

        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage(new IsEqual("Invalid Input for Encryption"));

        PowerMockito.when(spy.getCipherInstance()).thenThrow(new NoSuchAlgorithmException("error"));
        byte[] decrypted = spy.decrypt(testKey, ArrayUtils.subarray(encrypted, 0, 20), new byte[0]);
    }

    private static final String ENCRYPTION_ALGORITHM_NAME = "AES";

    @Test
    public void testAESGCMDecryptorForNEOCompatibility() {
        String encryptedValue = "ce73b8b30a8c7779e7e45c7a47319b654c9398f55ee71d7a5f4407ebe7618292fd18eb8e4f38140ba00d12fc62debb5c23cdef8aae0f91b39d0b39b17670dbd55d44516f336fc6ec04d4e2941cc94310b1f61170618ed97232dc15a42bc35d9cdc91";
        SecretKeySpec secretKey = new SecretKeySpec("3zTvzr3p67VC61jmV54rIYu1545x4TlY".getBytes(StandardCharsets.UTF_8), ENCRYPTION_ALGORITHM_NAME);
        AESGCMEncryptor aesgcmEncryptor = new AESGCMEncryptor();
        byte[] decryptedValue = aesgcmEncryptor.decrypt(secretKey, encryptedValue.getBytes(StandardCharsets.UTF_8), new byte[]{});
        assertEquals("Jeremy", new String(decryptedValue));
    }

    private static final int EXPECTED_IV_LENGTH = 12;
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    private byte[] decryptNEO(final Key key, byte[] toDecrypt, byte[] nonSecretData) {
        try {
            if (toDecrypt.length < EXPECTED_IV_LENGTH + 16) {
                LOG.error("Invalid input. Data was not encrypted by AESGCMEncryptor.");
                throw new EncryptionException("Invalid input. Data was not encrypted by AESGCMEncryptor.");
            }

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec params = new GCMParameterSpec(128, toDecrypt, 0, EXPECTED_IV_LENGTH);
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.updateAAD(nonSecretData);
            return cipher.doFinal(toDecrypt, EXPECTED_IV_LENGTH, toDecrypt.length - EXPECTED_IV_LENGTH);
        } catch(GeneralSecurityException gse) {
            LOG.error("Unable to perform Decryption: " + gse.getMessage(), gse);
            throw new EncryptionException("Unable to perform Decryption: ", gse);
        }
    }
}
