package au.gov.qld.dsiti.encryption.environment;

import au.gov.qld.dsiti.encryption.environment.kms.KmsConfigurationDecryptor;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.util.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.mockito.Mockito;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

/**
 * Created by jeremy on 29/8/17.
 */
public class EnvironmentConfigurationLoaderTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Test
    public void getValueNotEncrypted() throws Exception {
        ConfigurationDecryptor mockConfigurationDecryptor = Mockito.mock(ConfigurationDecryptor.class);
        EnvironmentConfigurationLoader loader = new EnvironmentConfigurationLoader(mockConfigurationDecryptor);
        ApplicationEnvironmentConfiguration settings = Mockito.mock(ApplicationEnvironmentConfiguration.class);
        Mockito.when(settings.getEnvironmentKey()).thenReturn("SOME_ENV_KEY");
        environmentVariables.set("SOME_ENV_KEY", "http://localhost:8080");
        Mockito.when(settings.getEncrypted()).thenReturn(false);
        assertEquals("http://localhost:8080", loader.getValue(settings));
        Mockito.verifyZeroInteractions(mockConfigurationDecryptor);
    }

    @Test
    public void getValueEncrypted() throws Exception {
        ConfigurationDecryptor mockConfigurationDecryptor = Mockito.mock(ConfigurationDecryptor.class);
        Mockito.when(mockConfigurationDecryptor.decrypt(Mockito.anyString())).thenReturn("http://localhost:8080");
        EnvironmentConfigurationLoader loader = new EnvironmentConfigurationLoader(mockConfigurationDecryptor);
        ApplicationEnvironmentConfiguration settings = Mockito.mock(ApplicationEnvironmentConfiguration.class);
        Mockito.when(settings.getEnvironmentKey()).thenReturn("SOME_ENV_KEY");
        Mockito.when(settings.getEncrypted()).thenReturn(true);

        environmentVariables.set("SOME_ENV_KEY", "alfhasldfjal;sjf;oajfas;ldfj");
        assertEquals("alfhasldfjal;sjf;oajfas;ldfj", System.getenv("SOME_ENV_KEY"));

        assertEquals("http://localhost:8080", loader.getValue(settings));
        Mockito.verify(mockConfigurationDecryptor, Mockito.times(1)).decrypt("alfhasldfjal;sjf;oajfas;ldfj");
    }

    @Test
    public void getValueEncryptedOnlyDecryptsOnce() throws Exception {
        AWSKMS mockKms = Mockito.mock(AWSKMS.class);
        DecryptResult result = new DecryptResult();
        result.setPlaintext(ByteBuffer.wrap("http://localhost:8080".getBytes(StandardCharsets.UTF_8)));

        Mockito.when(mockKms.decrypt(Mockito.any(DecryptRequest.class))).thenReturn(result);
        KmsConfigurationDecryptor decryptor = new KmsConfigurationDecryptor(mockKms);
        KmsConfigurationDecryptor spyKmsConfigurationDecryptor = Mockito.spy(decryptor);

        //Mockito.when(mockConfigurationDecryptor.decrypt(Mockito.anyString())).thenReturn("http://localhost:8080");
        EnvironmentConfigurationLoader loader = new EnvironmentConfigurationLoader(spyKmsConfigurationDecryptor);
        ApplicationEnvironmentConfiguration settings = Mockito.mock(ApplicationEnvironmentConfiguration.class);
        Mockito.when(settings.getEnvironmentKey()).thenReturn("SOME_ENV_KEY");
        Mockito.when(settings.getEncrypted()).thenReturn(true);

        EnvironmentConfigurationLoader spyEnvironmentConfigurationLoader = Mockito.spy(loader);

        String base64EncodedEnvValue = Base64.encodeAsString("alfhasldfjal;sjf;oajfas;ldfj".getBytes(StandardCharsets.UTF_8));
        environmentVariables.set("SOME_ENV_KEY", base64EncodedEnvValue);

        for (int i = 0; i < 10; i++) {
            assertEquals("http://localhost:8080", spyEnvironmentConfigurationLoader.getValue(settings));
        }
        Mockito.verify(spyKmsConfigurationDecryptor, Mockito.times(10)).decrypt(base64EncodedEnvValue);
        Mockito.verify(spyEnvironmentConfigurationLoader, Mockito.times(10)).getDecryptedValue(settings);
        Mockito.verify(mockKms, Mockito.times(1)).decrypt(Mockito.any(DecryptRequest.class));
    }

    @Test
    public void getDecryptedValue() throws Exception {
    }

}