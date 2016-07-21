package net.yan.kerberos.core.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * Created by yanle on 2016/7/21.
 */
public class SessionKeyProviderTest {
    private static final Log log = LogFactory.getLog(SessionKeyProviderTest.class);

    @Test
    public void generate() throws Exception {
        SessionKeyProvider provider = SessionKeyProvider.factory();
        String key = provider.generate();
        assertNotNull(key);
        log.info(key);
    }

}