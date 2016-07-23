package net.yan.kerberos.core.secure;

import javax.crypto.spec.DESedeKeySpec;

/**
 * A default setting. using {@code DESede } to encrypt/decrypt.
 */
public class DefaultCipherSettings implements CipherSettings {

    private String transformation;

    private String provider;

    private KeySpecGenerator keySpecGenerator;

    /**
     * {@inheritDoc}
     */
    public String getTransformation() {
        return transformation;
    }

    void setTransformation(String transformation) {
        this.transformation = transformation;
    }

    /**
     * {@inheritDoc}
     */
    public String getProvider() {
        return provider;
    }

    void setProvider(String provider) {
        this.provider = provider;
    }

    /**
     * {@inheritDoc}
     */
    public KeySpecGenerator getKeySpecGenerator() {
        return keySpecGenerator;
    }

    public void setKeySpecGenerator(KeySpecGenerator keySpecGenerator) {
        this.keySpecGenerator = keySpecGenerator;
    }

    public DefaultCipherSettings() {
        setTransformation("DESede");
        setKeySpecGenerator(key -> new DESedeKeySpec(key.getBytes()));
    }
}
