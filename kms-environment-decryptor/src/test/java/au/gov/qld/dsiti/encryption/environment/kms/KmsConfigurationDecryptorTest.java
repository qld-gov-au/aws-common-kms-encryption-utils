package au.gov.qld.dsiti.encryption.environment.kms;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.util.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

/**
 * Created by jeremy on 30/8/17.
 */
public class KmsConfigurationDecryptorTest {


    @Test
    public void decrypt() throws Exception {
        AWSKMS mockKms = mock(AWSKMS.class);
        KmsConfigurationDecryptor decryptor = new KmsConfigurationDecryptor(mockKms);

        String plainText = RandomStringUtils.random(50);
        String base64Encoded = Base64.encodeAsString(plainText.getBytes(StandardCharsets.UTF_8));

        DecryptResult decryptResult = new DecryptResult();
        decryptResult.setKeyId("alias/Key");
        decryptResult.setPlaintext(ByteBuffer.wrap(plainText.getBytes(StandardCharsets.UTF_8)));
        when(mockKms.decrypt(any(DecryptRequest.class))).thenReturn(decryptResult);

        DecryptRequest expectedDecryptRequest = new DecryptRequest();
        expectedDecryptRequest.setCiphertextBlob(ByteBuffer.wrap(plainText.getBytes(StandardCharsets.UTF_8)));

        String decrypted = decryptor.decrypt(base64Encoded);
        assertEquals(plainText, decrypted);
        verify(mockKms, times(1)).decrypt(eq(expectedDecryptRequest));
    }

}