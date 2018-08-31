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

}
