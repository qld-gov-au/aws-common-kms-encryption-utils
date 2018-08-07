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

    private String somePlainText = "11111111";

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
                "hQEMAzAbPOdBxmPvAgf/XPoU3m3ivPczI3aYKAtIPEnz6Y23Ssx1whNvc4/a+xbZ\n" +
                "0AWXnqFEZSUzpJDJShlLXo8QHnFXXhTaCtR7wxx42mQWhj+kxavS3XDic88Gp/5m\n" +
                "WsJ4q7W0oHbIgE7VgsiSG4rXK3l9jn6ueykLS5YLmVzRURRPSkb7KaYG/j2ODsl9\n" +
                "7hVYvgEFu9I3JgcWJ97lFhU//HktPUPgy75QxnMd6BOE3tTqekqbrVNl50b7UDVJ\n" +
                "14nplGX0irtiV3kaYAGY5n1ipsKQxiOa9+N6UBy4Ybxm8oFwRNILdkviElv6h415\n" +
                "ER5gxRVu5C2pacjJX8wcdubYLpnZ8f7oz/rsG0HeQck9efW4tPYbnOnujne1r0wN\n" +
                "2tcq+doSR/jOrHjtEjPBKiE7dgra1GxbdGFcNpK1DiBYDPpQndLNw41N4hdJ2g==\n" +
                "=v8tQ\n" +
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