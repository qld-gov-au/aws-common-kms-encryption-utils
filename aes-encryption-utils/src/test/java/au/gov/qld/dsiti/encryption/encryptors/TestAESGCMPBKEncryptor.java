package au.gov.qld.dsiti.encryption.encryptors;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by jeremy on 28/3/17.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({AESGCMEncryptor.class})
@PowerMockIgnore({"org.apache.http.conn.ssl.*", "javax.net.ssl.*" , "javax.crypto.*"})
public class TestAESGCMPBKEncryptor {


    private AESGCMPBKEncryptor aesgcmpbkEncryptor = new AESGCMPBKEncryptor();

    @Before
    public void init() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
    }
    
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testToString() {
        assertTrue(aesgcmpbkEncryptor.toString().contains("AES/GCM/NoPadding"));
        assertTrue(aesgcmpbkEncryptor.toString().contains("PBKDF2WithHmacSHA512"));
    }

    @Test
    public void testAESGCMDecryptorForNEOCompatibility() {
        //This is an actual encrypted value from Auth0 User app_metadata encrypted with the password below in DEV.
        String encryptedValueHex = "ce73b8b30a8c7779e7e45c7a47319b654c9398f55ee71d7a5f4407ebe7618292fd18eb8e4f38140ba00d12fc62debb5c23cdef8aae0f91b39d0b39b17670dbd55d44516f336fc6ec04d4e2941cc94310b1f61170618ed97232dc15a42bc35d9cdc91";
        byte[] decryptedValue = aesgcmpbkEncryptor.decryptHex("3zTvzr3p67VC61jmV54rIYu1545x4TlY".toCharArray(), encryptedValueHex);
        assertEquals("Jeremy", new String(decryptedValue));
    }

    @Test
    public void testAESGCMPBKEncryptor_LargeStrings() throws DecoderException {
        String plainText = RandomStringUtils.random(500);
        String sharedPassword = RandomStringUtils.randomAlphanumeric(32);
        String encryptedHex = aesgcmpbkEncryptor.encryptHex(sharedPassword.toCharArray(), plainText.getBytes());
        byte[] encryptedValue = Hex.decodeHex(encryptedHex.toCharArray());
        byte[] decryptedValue = aesgcmpbkEncryptor.decrypt(sharedPassword.toCharArray(), encryptedValue);
        assertEquals(plainText, new String(decryptedValue));
    }

    @Test
    public void testAESGCMPBKEncryptor_SmallStrings() throws DecoderException {
        String plainText = RandomStringUtils.random(5);
        String sharedPassword = RandomStringUtils.randomAlphanumeric(32);
        String encryptedHex = aesgcmpbkEncryptor.encryptHex(sharedPassword.toCharArray(), plainText.getBytes());
        byte[] encryptedValue = Hex.decodeHex(encryptedHex.toCharArray());
        byte[] decryptedValue = aesgcmpbkEncryptor.decrypt(sharedPassword.toCharArray(), encryptedValue);
        assertEquals(plainText, new String(decryptedValue));
    }



}
