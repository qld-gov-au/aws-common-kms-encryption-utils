package au.gov.qld.dsiti.encryption.encryptors;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.NoSuchProviderException;

/**
 * Interface for interacting with PGP
 */
public interface PGPEncryptor {

    /**
     * Decrypts a PGP Encrypted Message.
     *
     * @param pgpEncryptedMessage can be encrypted or encoded encrypted bytes
     * @return byte[] of decrypted message
     */
    byte[] decrypt(byte[] pgpEncryptedMessage) throws PGPException, IOException, InvalidCipherTextException;

    /**
     * Encrypts the PlainTextBytes and produces an "ArmouredOutput" byte[] encrypted with the PGP Public Encryption Key.
     *
     * @param plainTextBytesToEncrypt byte[] to encrypt
     * @return byte[] ArmouredOutput
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws PGPException
     */
    byte[] encryptAndEncode(byte[] plainTextBytesToEncrypt) throws NoSuchProviderException, IOException, PGPException;
}
