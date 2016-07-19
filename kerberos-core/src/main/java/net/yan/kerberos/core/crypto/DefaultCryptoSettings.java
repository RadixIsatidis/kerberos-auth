package net.yan.kerberos.core.crypto;

import javax.crypto.spec.DESedeKeySpec;

public class DefaultCryptoSettings extends CryptoSettings {

    public DefaultCryptoSettings() {
        super();
        setTransformation("DESede");
        setKeySpecGenerator(key -> new DESedeKeySpec(key.getBytes()));
    }
}
