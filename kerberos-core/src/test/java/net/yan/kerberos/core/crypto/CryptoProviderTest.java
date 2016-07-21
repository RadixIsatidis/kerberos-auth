package net.yan.kerberos.core.crypto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESedeKeySpec;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import static org.junit.Assert.*;

public class CryptoProviderTest {

    private static final Log log = LogFactory.getLog(CryptoProviderTest.class);

    private CryptoProvider cryptoProvider;

    private final static String key = "test key test key test key test key test key test key test key";

    @Before
    public void setup() {
        if (null == cryptoProvider)
            cryptoProvider = new CryptoProvider();
    }

    @Test
    public void testCrypto() throws GeneralSecurityException, IOException, ClassNotFoundException {
        SecretKey secretKey = cryptoProvider.generateKey(key);
        assertNotNull(secretKey);

        KeySpec keySpec = new DESedeKeySpec(key.getBytes());
        SecretKey _secretKey = cryptoProvider.generateKey(keySpec);
        assertEquals(secretKey, _secretKey);

        log.info(new String(secretKey.getEncoded()));
        log.info(new String(_secretKey.getEncoded()));

        String strToEncrypt = "my secret.";

        String t1 = cryptoProvider.encryptString(strToEncrypt, keySpec);
        assertNotNull(t1);
        assertTrue(t1.length() > 0);
        String t2 = cryptoProvider.encryptString(strToEncrypt, secretKey);
        assertNotNull(t2);
        assertTrue(t2.length() > 0);

        assertEquals(t1, t2);

        String t3 = cryptoProvider.decryptString(t1, keySpec);
        assertNotNull(t3);
        assertTrue(t3.length() > 0);
        assertEquals(strToEncrypt, t3);

        String t4 = cryptoProvider.decryptString(t1, secretKey);
        assertNotNull(t4);
        assertTrue(t4.length() > 0);
        assertEquals(strToEncrypt, t4);

        String t5 = cryptoProvider.decryptString(t2, keySpec);
        assertNotNull(t5);
        assertTrue(t5.length() > 0);
        assertEquals(strToEncrypt, t5);

        String t6 = cryptoProvider.decryptString(t2, secretKey);
        assertNotNull(t6);
        assertTrue(t6.length() > 0);
        assertEquals(strToEncrypt, t6);

        Crypto o1 = new Crypto();
        o1.a = strToEncrypt;
        o1.b = 2;
        o1.c = false;
        o1.d = 5.5;

        String t7 = cryptoProvider.encryptObject(o1, key);
        assertNotNull(t7);
        log.info(t7);
        Crypto o2 = cryptoProvider.decryptObject(t7, key);
        assertEquals(o1, o2);
    }

    public static class Crypto implements Serializable {
        private String a;
        private int b;

        private boolean c;

        private double d;

        public String getA() {
            return a;
        }

        public void setA(String a) {
            this.a = a;
        }

        public int getB() {
            return b;
        }

        public void setB(int b) {
            this.b = b;
        }

        public boolean isC() {
            return c;
        }

        public void setC(boolean c) {
            this.c = c;
        }

        public double getD() {
            return d;
        }

        public void setD(double d) {
            this.d = d;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Crypto)) return false;

            Crypto crypto = (Crypto) o;

            if (getB() != crypto.getB()) return false;
            if (isC() != crypto.isC()) return false;
            if (Double.compare(crypto.getD(), getD()) != 0) return false;
            return getA() != null ? getA().equals(crypto.getA()) : crypto.getA() == null;

        }

        @Override
        public int hashCode() {
            int result;
            long temp;
            result = getA() != null ? getA().hashCode() : 0;
            result = 31 * result + getB();
            result = 31 * result + (isC() ? 1 : 0);
            temp = Double.doubleToLongBits(getD());
            result = 31 * result + (int) (temp ^ (temp >>> 32));
            return result;
        }
    }
}