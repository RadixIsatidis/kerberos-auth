package net.yan.kerberos.core.crypto;

public class CryptoSettings {

    private String transformation;

    private String provider;

    private KeySpecGenerator keySpecGenerator;

    public String getTransformation() {
        return transformation;
    }

    void setTransformation(String transformation) {
        this.transformation = transformation;
    }

    public String getProvider() {
        return provider;
    }

    void setProvider(String provider) {
        this.provider = provider;
    }

    public KeySpecGenerator getKeySpecGenerator() {
        return keySpecGenerator;
    }

    public void setKeySpecGenerator(KeySpecGenerator keySpecGenerator) {
        this.keySpecGenerator = keySpecGenerator;
    }

    CryptoSettings() {
    }
}
