package net.yan.kerberos.core.crypto;

public class CryptoSettingBuilder {

    private String transformation;

    private String provider;

    private KeySpecGenerator keySpecGenerator;

    public String getTransformation() {
        return transformation;
    }

    public void setTransformation(String transformation) {
        this.transformation = transformation;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public KeySpecGenerator getKeySpecGenerator() {
        return keySpecGenerator;
    }

    public void setKeySpecGenerator(KeySpecGenerator keySpecGenerator) {
        this.keySpecGenerator = keySpecGenerator;
    }

    public CryptoSettings build() {
        CryptoSettings settings = new CryptoSettings();
        settings.setTransformation(getTransformation());
        settings.setProvider(getProvider());
        settings.setKeySpecGenerator(getKeySpecGenerator());
        return settings;
    }
}
