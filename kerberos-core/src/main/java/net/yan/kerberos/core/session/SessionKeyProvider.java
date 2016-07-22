package net.yan.kerberos.core.session;


import java.security.GeneralSecurityException;

/**
 * Class that providing session key generation service.
 */
public class SessionKeyProvider {

    private final SessionSettings _settings;

    private static SessionKeyProvider sessionKeyProvider;

    public SessionSettings getSettings() {
        return _settings;
    }

    private SessionKeyProvider(SessionSettings settings) {
        _settings = settings;
    }

    public static SessionKeyProvider factory() {
        return factory(new DefaultSessionSettings());
    }

    public static SessionKeyProvider factory(SessionSettings settings) {
        if (null == sessionKeyProvider) {
            sessionKeyProvider = new SessionKeyProvider(settings);
        }
        return sessionKeyProvider;
    }

    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_UPPER =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /**
     * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
     * The returned array will be double the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data     a byte[] to convert to Hex characters
     * @param toDigits the output alphabet
     * @return A char[] containing hexadecimal characters
     * @since 1.4
     */
    private static char[] encodeHex(final byte[] data, final char[] toDigits) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
        return out;
    }

    /**
     * Generate a session key.
     *
     * @return session key string
     * @throws GeneralSecurityException any security exception.
     */
    public String generate() throws GeneralSecurityException {
        SessionKeyFactory provider = _settings.getSessionKeyFactory();
        return new String(encodeHex(provider.getSessionKey(_settings), DIGITS_UPPER));
    }
}
