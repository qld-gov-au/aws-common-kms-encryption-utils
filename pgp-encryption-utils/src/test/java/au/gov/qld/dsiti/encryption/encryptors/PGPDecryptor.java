package au.gov.qld.dsiti.encryption.encryptors;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.*;
import java.security.NoSuchProviderException;

/**
 * Utility test class for decrypting input
 */
public class PGPDecryptor {

    public static void main(String[] args) {

        if (args.length < 4) {
            System.out.println("Requires 4 Arguments: <key_id> <pass_phrase> <publick key file> <private key file>");
            System.exit(-1);
        }

        String keyId = args[0];
        String passPhrase = args[1];
        String pgpKeyRing = args[2];
        String publicKeyRing = args[3];
        String fileToEncrypt = args[4];

        try {
            //PGPPublicKey pubKey = PGPUtils.readPublicKeyFromCol(new FileInputStream(publicKeyRing));
            PGPPublicKey pubKey = PGPUtils.readPublicKeyFromCol(new FileInputStream(publicKeyRing));

            String plainTextContents = new String(IOUtils.toByteArray(new FileInputStream(fileToEncrypt)));
            System.out.println("Input: " + plainTextContents);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PGPUtils.encryptFile(os, fileToEncrypt, pubKey);
            byte[] encrypted =  os.toByteArray();
            System.out.println("Encrypted: " + new String(encrypted));
            InputStream is = new ByteArrayInputStream(encrypted);
            ByteArrayOutputStream decrypted = PGPUtils.decryptFile(is, new FileInputStream(pgpKeyRing), new FileInputStream(publicKeyRing), passPhrase.toCharArray());
            System.out.println("Decrypted: " + new String(decrypted.toByteArray()));
        } catch (PGPException e) {
            e.printStackTrace();
            //fail("exception: " + e.getMessage(), e.getUnderlyingException());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }

    }

}
