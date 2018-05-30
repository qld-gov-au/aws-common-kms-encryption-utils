package au.gov.qld.dsiti.encryption.encryptors;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * This test uses the previously generated keys to encrypted and decrypt text.
 */
public class PGPBCEncryptorTest {

    private PGPBCEncryptor pgpbcEncryptor;

    private String somePlainText = "123456789abcd";

    @Before
    public void setUp() throws Exception {
        pgpbcEncryptor = new PGPBCEncryptor(this.getClass().getResourceAsStream("/test_pgp.asc"),
                this.getClass().getResourceAsStream("/test_pgp.pkr"),
                "123456789");
    }

    @Test
    public void decrypt() throws Exception {
        byte[] encryptedMessageBytes = ("-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.59\n" +
                "\n" +
                "hQEMA8aNf5XDd6SdAggAjFL8+CaNaC2/pCsZPlTKfH/B/alsuF5Vl2GQ0cKnhb2q\n" +
                "kWJpb7VhwgcEY9fF3JhtIy0nqIWGoU6nku/i0v0eNnqb16TU3ZdixsLZr+kiPRa9\n" +
                "zZ4J+vJQmf2mwsIiEJ2Q5BvkGiqwwea2NHNbLyqsn/XOxz9dL0uRk8wnT1Y83PuH\n" +
                "5qZaWxZcBJSZEZRBXekgcgAZqU6eRLwIm1+2KuT0FNdZnZCltb3IDHKjGiFDTAvE\n" +
                "yEF5BmL1n6SztGwnNX8hy7jVczjw2m5VtwQNN7axMv8UDDr1HPt2DObMcEiZy+xm\n" +
                "WoiDS7I0ukfdK4adBpPFGttPmd5iZ4+MNNlBTCV5i8lHSYya5ncuHvT7Uk+OTaaf\n" +
                "XGyH7tXyCB4Uhx8W7t042kZEOw/XlSzmR/dO8PMVKf/TEnWXghctqxBiBAshi8VP\n" +
                "prUMiT7J0mU=\n" +
                "=0NCh\n" +
                "-----END PGP MESSAGE-----").getBytes();

        byte[] decrypted = pgpbcEncryptor.decrypt(encryptedMessageBytes);
        String decryptedString = new String(decrypted);
        System.out.println("Decrypted:\n" + decryptedString);
        assertEquals(somePlainText, decryptedString);
    }

    @Test
    public void encryptAndEncode() throws Exception {
        byte[] encryptedAndEncoded = pgpbcEncryptor.encryptAndEncode(somePlainText.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted:\n" + new String(encryptedAndEncoded));

        byte[] decrypted = pgpbcEncryptor.decrypt(encryptedAndEncoded);
        String decryptedString = new String(decrypted);
        System.out.println("Decrypted:\n" + decryptedString);
        assertEquals(somePlainText, decryptedString);
    }

}