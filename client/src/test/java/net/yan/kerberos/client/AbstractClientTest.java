package net.yan.kerberos.client;

import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.core.secure.CipherProvider;

public abstract class AbstractClientTest {
    protected CipherProvider cipherProvider = new CipherProvider();

    protected ClientSettings clientSettings = new ClientSettings() {
        @Override
        public Long getSessionLifeTime() {
            return 30 * 60 * 1000L;
        }

        @Override
        public String getMasterKey() {
            return "My client master key, hope it long enough.";
        }

        @Override
        public int getRetryTimes() {
            return 3;
        }

        @Override
        public String getLocalName() {
            return "username";
        }
    };
}
