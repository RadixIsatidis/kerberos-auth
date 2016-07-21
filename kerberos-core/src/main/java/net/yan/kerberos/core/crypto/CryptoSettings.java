package net.yan.kerberos.core.crypto;

/**
 * The crypto settings.
 */
public interface CryptoSettings {

    /**
     * @return the name of the transformation, e.g.,
     * <i>DES/CBC/PKCS5Padding</i>.
     * See the Cipher section in the <a href=
     * "http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard transformation names.
     * <p>
     * Every implementation of the Java platform is required to support
     * the following standard <code>Cipher</code> transformations with the keysizes
     * in parentheses:
     * <ul>
     * <li><tt>AES/CBC/NoPadding</tt> (128)</li>
     * <li><tt>AES/CBC/PKCS5Padding</tt> (128)</li>
     * <li><tt>AES/ECB/NoPadding</tt> (128)</li>
     * <li><tt>AES/ECB/PKCS5Padding</tt> (128)</li>
     * <li><tt>DES/CBC/NoPadding</tt> (56)</li>
     * <li><tt>DES/CBC/PKCS5Padding</tt> (56)</li>
     * <li><tt>DES/ECB/NoPadding</tt> (56)</li>
     * <li><tt>DES/ECB/PKCS5Padding</tt> (56)</li>
     * <li><tt>DESede/CBC/NoPadding</tt> (168)</li>
     * <li><tt>DESede/CBC/PKCS5Padding</tt> (168)</li>
     * <li><tt>DESede/ECB/NoPadding</tt> (168)</li>
     * <li><tt>DESede/ECB/PKCS5Padding</tt> (168)</li>
     * <li><tt>RSA/ECB/PKCS1Padding</tt> (1024, 2048)</li>
     * <li><tt>RSA/ECB/OAEPWithSHA-1AndMGF1Padding</tt> (1024, 2048)</li>
     * <li><tt>RSA/ECB/OAEPWithSHA-256AndMGF1Padding</tt> (1024, 2048)</li>
     * </ul>
     * @see javax.crypto.Cipher
     */
    String getTransformation();

    /**
     * @return the name of the provider.
     */
    String getProvider();

    /**
     * @return A {@link KeySpecGenerator} to generate a {@link java.security.spec.KeySpec} using a key string.
     */
    KeySpecGenerator getKeySpecGenerator();

}
