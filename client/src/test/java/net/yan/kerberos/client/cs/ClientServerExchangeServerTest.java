package net.yan.kerberos.client.cs;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.crypto.*"})
@PrepareForTest(ClientServerExchangeServer.class)
public class ClientServerExchangeServerTest {
    @Test
    public void clientServerExchange() throws Exception {

    }

}