package net.yan.kerberos.core.secure;

public class CipherSettingBuilder {

    private String transformation;

    private String provider;

    private KeySpecGenerator keySpecGenerator;

    public String getTransformation() {
        return transformation;
    }

    public CipherSettingBuilder setTransformation(String transformation) {
        this.transformation = transformation;
        return this;
    }

    public String getProvider() {
        return provider;
    }

    public CipherSettingBuilder setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    public KeySpecGenerator getKeySpecGenerator() {
        return keySpecGenerator;
    }

    public CipherSettingBuilder setKeySpecGenerator(KeySpecGenerator keySpecGenerator) {
        this.keySpecGenerator = keySpecGenerator;
        return this;
    }

    public CipherSettings build() {
        final String _transformation = getTransformation();
        final String _provider = getProvider();
        final KeySpecGenerator _keySpecGenerator = getKeySpecGenerator();
        return new CipherSettings() {
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

    public CipherSettings buildDefault() {
        return new DefaultCipherSettings();
    }
}
