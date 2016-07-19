package net.yan.kerberos.core.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.KeySpec;

public interface CryptoProvider {

    Cipher getCipher(CryptoSettings settings) throws GeneralSecurityException;

    SecretKey generateKey(CryptoSettings settings, KeySpec keySpec) throws GeneralSecurityException;

    SecretKey generateKey(CryptoSettings settings, String key) throws GeneralSecurityException;
}
