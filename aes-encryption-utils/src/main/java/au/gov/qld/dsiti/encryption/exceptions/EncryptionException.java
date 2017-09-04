package au.gov.qld.dsiti.encryption.exceptions;

/**
 * Created by jeremy on 1/9/17.
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
