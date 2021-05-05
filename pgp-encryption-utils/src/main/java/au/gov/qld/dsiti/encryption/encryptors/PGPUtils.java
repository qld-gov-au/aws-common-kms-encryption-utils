package au.gov.qld.dsiti.encryption.encryptors;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.UUID;

public class PGPUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static ByteArrayOutputStream decryptFile(InputStream in, InputStream secKeyIn, InputStream pubKeyIn, char[] pass) throws IOException, PGPException, InvalidCipherTextException {
        PGPPublicKey pubKey = readPublicKeyFromCol(pubKeyIn);

        PGPSecretKey secKey = readSecretKeyFromCol(secKeyIn, pubKey.getKeyID());

        return decryptPGPMessage(in, secKey, pass);
    }

    public static ByteArrayOutputStream decryptPGPMessage(InputStream encryptedInput, PGPSecretKey secKey, char[] pass) throws IOException, PGPException, InvalidCipherTextException {
        InputStream decodedEncryptedInput = PGPUtil.getDecoderStream(encryptedInput);

        JcaPGPObjectFactory pgpFact;

        PGPObjectFactory pgpF = new PGPObjectFactory(decodedEncryptedInput, new BcKeyFingerprintCalculator());

        Object o = pgpF.nextObject();
        PGPEncryptedDataList encList;

        if (o instanceof PGPEncryptedDataList) {
            encList = (PGPEncryptedDataList) o;
        } else {
            encList = (PGPEncryptedDataList) pgpF.nextObject();
        }

        Iterator<PGPEncryptedData> itt = encList.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData encP = null;
        while (sKey == null && itt.hasNext()) {
            encP = (PGPPublicKeyEncryptedData) itt.next();
            sKey = secKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));
        }
        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

        pgpFact = new JcaPGPObjectFactory(clear);


        Object nextFact = pgpFact.nextObject();

        InputStream factInputStream = ((PGPCompressedData) nextFact).getDataStream();
        pgpFact = new JcaPGPObjectFactory(factInputStream);

        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        InputStream inLd = ld.getDataStream();

        int ch;
        while ((ch = inLd.read()) >= 0) {
            bOut.write(ch);
        }

        return bOut;
    }

    public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey) throws IOException, NoSuchProviderException, PGPException {

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));

        comData.close();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setSecureRandom(new SecureRandom()));

        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes);

        cOut.close();

        out.close();
    }

    public static void encryptAndEncodeBytes(OutputStream out, byte[] plainTextToEncrypt, PGPPublicKey encKey) throws IOException, NoSuchProviderException, PGPException {

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(comData.open(bOut), PGPLiteralData.BINARY, UUID.randomUUID().toString(), plainTextToEncrypt.length, new Date());
        pOut.write(plainTextToEncrypt);
        pOut.close();
        comData.close();

        byte[] bytes = bOut.toByteArray();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setSecureRandom(new SecureRandom()));
        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

        ArmoredOutputStream aos = new ArmoredOutputStream(out);
        OutputStream cOut = cPk.open(aos, bytes.length);
        cOut.write(bytes);
        cOut.close();
        aos.close();
        out.close();
    }

    /**
     * Load a secret key ring collection from keyIn and find the private key corresponding to
     * keyID if it exists.
     *
     * @param keyIn input stream representing a key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public  static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException, NoSuchProviderException
    {
        //1/26/15 added Jca prefix to avoid eclipse warning, also used https://www.bouncycastle.org/docs/pgdocs1.5on/index.html
        PGPSecretKeyRingCollection pgpSec = new JcaPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
        return findPrivateKey(pgpSec.getSecretKey(keyID), pass);

    }

    public static PGPSecretKey readSecretKeyFromCol(InputStream in, long keyId) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());

        PGPSecretKey key = pgpSec.getSecretKey(keyId);

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }

    @SuppressWarnings("rawtypes")
    public static PGPPublicKey readPublicKeyFromCol(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPPublicKey key = null;
        Iterator rIt = pgpPub.getKeyRings();
        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();
            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();
                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }


    @SuppressWarnings("rawtypes")
    public static PGPPublicKey readPublicKeyFromPGPPublicKeyRing(PGPPublicKeyRing kRing) throws IOException, PGPException {
        PGPPublicKey key = null;
        Iterator kIt = kRing.getPublicKeys();
        while (key == null && kIt.hasNext()) {
            PGPPublicKey k = (PGPPublicKey) kIt.next();
            if (k.isEncryptionKey()) {
                key = k;
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }

    /**
     * Load a secret key and find the private key in it
     * @param pgpSecKey The secret key
     * @param pass passphrase to decrypt secret key with
     * @return
     * @throws PGPException
     */
    public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass)
            throws PGPException
    {
        if (pgpSecKey == null) return null;

        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
        return pgpSecKey.extractPrivateKey(decryptor);
    }


}
