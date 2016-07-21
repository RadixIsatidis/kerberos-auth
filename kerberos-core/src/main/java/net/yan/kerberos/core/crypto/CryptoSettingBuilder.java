package net.yan.kerberos.core.crypto;

public class CryptoSettingBuilder {

    private String transformation;

    private String provider;

    private KeySpecGenerator keySpecGenerator;

    public String getTransformation() {
        return transformation;
    }

    public CryptoSettingBuilder setTransformation(String transformation) {
        this.transformation = transformation;
        return this;
    }

    public String getProvider() {
        return provider;
    }

    public CryptoSettingBuilder setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    public KeySpecGenerator getKeySpecGenerator() {
        return keySpecGenerator;
    }

    public CryptoSettingBuilder setKeySpecGenerator(KeySpecGenerator keySpecGenerator) {
        this.keySpecGenerator = keySpecGenerator;
        return this;
    }

    public CryptoSettings build() {
        final String _transformation = getTransformation();
        final String _provider = getProvider();
        final KeySpecGenerator _keySpecGenerator = getKeySpecGenerator();
        return new CryptoSettings() {
            @Override
            public String getTransformation() {
                return _transformation;
            }

            @Override
            public String getProvider() {
                return _provider;
            }

            @Override
            public KeySpecGenerator getKeySpecGenerator() {
                return _keySpecGenerator;
            }
        };
    }

    public CryptoSettings buildDefault() {
        return new DefaultCryptoSettings();
    }
}
