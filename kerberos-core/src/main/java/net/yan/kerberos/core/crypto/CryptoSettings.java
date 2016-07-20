package net.yan.kerberos.core.crypto;

/**
 * The crypto settings.
 */
public interface CryptoSettings {

    /**
     * @return the name of the transformation, e.g.,
     * <i>DES/CBC/PKCS5Padding</i>.
     * See the Cipher section in the <a href=
     * "{@docRoot}/../technotes/guides/security/StandardNames.html#Cipher">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard transformation names.
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
