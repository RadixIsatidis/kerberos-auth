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
        final String _transformation = transformation;
        final String _provider = provider;
        final KeySpecGenerator _keySpecGenerator = keySpecGenerator;
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
