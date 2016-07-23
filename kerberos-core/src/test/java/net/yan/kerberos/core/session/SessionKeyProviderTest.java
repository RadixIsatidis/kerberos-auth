package net.yan.kerberos.core.session;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertNotNull;

/**
 * Created by yanle on 2016/7/21.
 */
public class SessionKeyProviderTest {
    private static final Logger log = LoggerFactory.getLogger(SessionKeyProviderTest.class);

    @Test
    public void generate() throws Exception {
        SessionKeyProvider provider = SessionKeyProvider.factory();
        String key = provider.generate();
        assertNotNull(key);
        log.info(key);
    }

}