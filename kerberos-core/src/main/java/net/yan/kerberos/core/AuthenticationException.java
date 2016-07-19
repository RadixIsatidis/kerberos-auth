package net.yan.kerberos.core;

/**
 * Abstract superclass for all exceptions related to certification process.
 */
public abstract class AuthenticationException extends RuntimeException {

    /**
     * Constructs an {@code AuthenticationException} with the specified message and no
     * root cause.
     *
     * @param message the detail message
     */
    public AuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs an {@code AuthenticationException} with the specified message and root
     * cause.
     *
     * @param message the detail message
     * @param cause   the root cause
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
