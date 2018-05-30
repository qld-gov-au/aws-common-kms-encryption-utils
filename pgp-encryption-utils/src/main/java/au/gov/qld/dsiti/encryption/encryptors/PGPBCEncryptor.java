package au.gov.qld.dsiti.encryption.encryptors;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.*;
import java.security.NoSuchProviderException;

import static au.gov.qld.dsiti.encryption.encryptors.PGPUtils.*;

/**
 * Implementation of the PGPEncryptor using BouncyCastle
 *
 */
public class PGPBCEncryptor implements PGPEncryptor {

    private final PGPSecretKey secretKey;
    private final PGPPublicKey publicEncryptionKey;
    private final char[] secretKeyPassPhrase;


    /**
     * Constructor
     *
     * @param secKeyIn InputStream for the PGP Secret Key Ring (typically loaded from a .asc file)
     * @param pubKeyIn InputStream for the PGP Public Key Ring (typically loaded from a .pkr file)
     * @param secretKeyPassPhrase PassPhrase for the PGP Secret Key Ring
     * @throws IOException
     * @throws PGPException
     */
    public PGPBCEncryptor(InputStream secKeyIn, InputStream pubKeyIn, String secretKeyPassPhrase) throws IOException, PGPException {
        publicEncryptionKey = readPublicKeyFromCol(pubKeyIn);
        secretKey = readSecretKeyFromCol(secKeyIn, publicEncryptionKey.getKeyID());
        this.secretKeyPassPhrase = secretKeyPassPhrase.toCharArray();
    }

    @Override
    public byte[] decrypt(byte[] pgpEncryptedMessage) throws PGPException, IOException, InvalidCipherTextException {
        return decryptPGPMessage(new ByteArrayInputStream(pgpEncryptedMessage), secretKey, secretKeyPassPhrase).toByteArray();
    }

    public byte[] encryptAndEncode(byte[] plainTextBytesToEncrypt) throws NoSuchProviderException, IOException, PGPException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        encryptAndEncodeBytes(byteArrayOutputStream, plainTextBytesToEncrypt, publicEncryptionKey);
        return byteArrayOutputStream.toByteArray();
    }
}
