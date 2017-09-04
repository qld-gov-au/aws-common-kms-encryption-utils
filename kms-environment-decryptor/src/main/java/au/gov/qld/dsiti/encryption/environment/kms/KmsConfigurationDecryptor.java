package au.gov.qld.dsiti.encryption.environment.kms;

import au.gov.qld.dsiti.encryption.environment.ConfigurationDecryptor;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.InvalidCiphertextException;
import com.amazonaws.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of the ConfigurationDecryptor that uses KMS to decrypt the values.
 *
 * Decrypted keys are cached for performance reasons.
 */
public class KmsConfigurationDecryptor implements ConfigurationDecryptor {

    private static final Logger LOG = LoggerFactory.getLogger(KmsConfigurationDecryptor.class);

    private final AWSKMS client;
    private static final String EMPTY_STRING = "";

    private static final Map<String, String> decryptedValues = new ConcurrentHashMap<>();

    public KmsConfigurationDecryptor(AWSKMS client) {
        this.client = client;
        LOG.debug("Creating new KMSConfigurationDecryptor");
    }

    @Override
    public String decrypt(String encryptedConfigurationValue) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("decrypting '%s' with KMS", encryptedConfigurationValue));
        }

        if (encryptedConfigurationValue == null || encryptedConfigurationValue.isEmpty()) {
            return EMPTY_STRING;
        }

        return decryptedValues.computeIfAbsent(encryptedConfigurationValue, s -> {
            byte[] encryptedKey = Base64.decode(encryptedConfigurationValue);
            DecryptRequest request = new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(encryptedKey));
            try {
                ByteBuffer plainTextKey = client.decrypt(request).getPlaintext();
                return new String(plainTextKey.array(), StandardCharsets.UTF_8);
            } catch (InvalidCiphertextException ice) {
                LOG.warn(String.format("Unable to decrypt '%s', was the value actually encrypted with KMS? Returning raw value.", encryptedConfigurationValue));
                return encryptedConfigurationValue;
            }
        });
    }
}
