package net.yan.kerberos.core.crypto;

import java.security.InvalidKeyException;
import java.security.spec.KeySpec;

public interface KeySpecGenerator {

    KeySpec generator(String key) throws InvalidKeyException;
}
