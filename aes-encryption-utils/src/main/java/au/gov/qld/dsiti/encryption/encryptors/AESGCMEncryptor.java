package au.gov.qld.dsiti.encryption.encryptors;

import au.gov.qld.dsiti.encryption.exceptions.EncryptionException;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

/**
 * AES GCM Encryption utility
 */
final class AESGCMEncryptor implements AESEncryptor {

    private static final String INVALID_INPUT_EXCEPTION_MESSAGE = "Invalid Input for Encryption";
    private static final String GENERIC_ENCRYPTION_EXCEPTION_MESSAGE = "Encryption Exception";

    private static String ALGORITHM = "AES/GCM/NoPadding";

    private static int EXPECTED_IV_LENGTH = 12;

    private static byte[] version = "G1".getBytes(StandardCharsets.UTF_8);

    private static final Logger LOG = LoggerFactory.getLogger(AESGCMEncryptor.class);

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public byte[] encrypt(final Key key, byte[] toEncrypt, byte[] nonSecretData) {
        try {
            byte[] iv = generateIV();
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(16 * Byte.SIZE, iv));
            cipher.updateAAD(nonSecretData);

            byte[] cipherText = cipher.doFinal(toEncrypt);
            assert cipherText.length == toEncrypt.length + 16;

            byte[] message = new byte[EXPECTED_IV_LENGTH + toEncrypt.length + 16];

            System.arraycopy(iv, 0, message, 0, EXPECTED_IV_LENGTH);
            System.arraycopy(cipherText, 0, message, EXPECTED_IV_LENGTH, cipherText.length);
            return message;

        } catch (IllegalArgumentException  iae) {
            LOG.error(INVALID_INPUT_EXCEPTION_MESSAGE + ": " + iae.getMessage(), iae);
            throw new EncryptionException(INVALID_INPUT_EXCEPTION_MESSAGE, iae);
        } catch (GeneralSecurityException gse) {
            LOG.error("Unable to perform Encryption: " + gse.getMessage(), gse);
            throw new EncryptionException(GENERIC_ENCRYPTION_EXCEPTION_MESSAGE, gse);
        }
    }

    @Override
    public byte[] decrypt(final Key key, byte[] toDecrypt, byte[] nonSecretData) {
        try {
            if (toDecrypt.length < EXPECTED_IV_LENGTH + 16) {
                LOG.error("Invalid input. Data was not encrypted by AESGCMEncryptor.");
                throw new EncryptionException(INVALID_INPUT_EXCEPTION_MESSAGE);
            }

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec params = new GCMParameterSpec(128, toDecrypt, 0, EXPECTED_IV_LENGTH);
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.updateAAD(nonSecretData);
            return cipher.doFinal(toDecrypt, EXPECTED_IV_LENGTH, toDecrypt.length - EXPECTED_IV_LENGTH);
        } catch(GeneralSecurityException gse) {
            LOG.error("Unable to perform Decryption: " + gse.getMessage(), gse);
            throw new EncryptionException(GENERIC_ENCRYPTION_EXCEPTION_MESSAGE, gse);
        }
    }

    private byte[] generateIV() {
        byte[] bytes = new byte[EXPECTED_IV_LENGTH];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("ALGORITHM", ALGORITHM)
                .toString();
    }

    @Override
    public byte[] getVersion() {
        return version.clone();
    }
}
