package net.yan.kerberos.core.secure;

import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.Assert.assertNotNull;

/**
 * Created by yanle on 2016/7/21.
 */
public class CipherSettingBuilderTest {
    @Test
    public void build() throws Exception {
        CipherSettingBuilder builder = new CipherSettingBuilder();
        CipherSettings settings = builder
                .setTransformation("AES/CBC/PKCS5Padding")
                .setKeySpecGenerator(key -> {
                    try {
                        byte[] bytes = key.getBytes("UTF-8");
                        MessageDigest sha = MessageDigest.getInstance("SHA-1");
                        bytes = sha.digest(bytes);
                        bytes = Arrays.copyOf(bytes, 16); // use only first 128 bit
                        return new SecretKeySpec(bytes, "AES");
                    } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        return null;
                    }
                })
                .build();
        assertNotNull(settings);
    }

}