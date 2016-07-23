package net.yan.kerberos.kdc.userdetails;

import net.yan.kerberos.core.AuthenticationException;

/**
 * Thrown if an {@link UserDetailsService} implementation cannot locate a {@link UserDetails} by
 * its username.
 */
public class UsernameNotFoundException extends AuthenticationException {

    /**
     * Constructs a <code>UsernameNotFoundException</code> with the specified message.
     *
     * @param message the detail message.
     */
    public UsernameNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code UsernameNotFoundException} with the specified message and root
     * cause.
     *
     * @param message the detail message.
     * @param cause   root cause
     */
    public UsernameNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
