package net.yan.kerberos.client.cs;

import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import net.yan.kerberos.data.ServerTicket;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Objects;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.crypto.*"})
@PrepareForTest(ClientServerExchangeServer.class)
public class ClientServerExchangeServerTest {

    private static final Logger logger = LoggerFactory.getLogger(ClientServerExchangeServerTest.class);

    private CipherProvider cipherProvider = new CipherProvider();

    private ClientServerExchangeRequest request;
    private String SERVER_NAME = "LOCALHOST";
    private String SK_TGS = "SESSION-KEY-TICKET-GRANTING-SERVER-HOPE-IT-LONG-ENOUGH";
    private String SK_SERVER = "SESSION-KEY-CLIENT-SERVER-HOPE-IT-LONG-ENOUGH";
    private Authenticator clientAuth;
    private Authenticator serverAuth;
    private ServerTicket serverTicket;

    @Before
    public void setUp() throws Exception {
        if (null == clientAuth) {
            clientAuth = new Authenticator();
            clientAuth.setLifeTime(30 * 60 * 1000L);
            clientAuth.setStartTime(Instant.now().toEpochMilli());
            clientAuth.setAddress("localhost");
            clientAuth.setUsername("client-username");
        }

        if (null == serverAuth) {
            serverAuth = new Authenticator();
            serverAuth.setUsername(SERVER_NAME);
            serverAuth.setAddress("localhost");
            serverAuth.setLifeTime(30 * 60 * 1000L);
            serverAuth.setStartTime(Instant.now().toEpochMilli());
        }

        if (null == serverTicket) {
            serverTicket = new ServerTicket();
            serverTicket.setStartTime(Instant.now().toEpochMilli());
            serverTicket.setUsername(SERVER_NAME);
            serverTicket.setAddress("localhost");
            serverTicket.setSessionKey(SK_SERVER);
        }

        if (null == request) {
            request = new ClientServerExchangeRequest();
            request.setAuthenticator(cipherProvider.encryptObject(clientAuth, SK_SERVER));
            request.setServerName(SERVER_NAME);
            request.setServerTicket(cipherProvider.encryptObject(serverTicket, SK_TGS));
        }

    }

    private boolean verify(String name, Authenticator authenticator) throws ServerVerifyException {
        return Objects.equals(clientAuth, authenticator);
    }

    private void csExchange(ClientServerExchangeResponse response) {
        String s = response.getAuthenticator();
        try {
            Authenticator auth = cipherProvider.decryptObject(s, SK_SERVER);
            assertEquals(serverAuth, auth);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void clientServerExchange() throws Exception {
        ClientServerExchangeServer server = new ClientServerExchangeServer();
        server.setCipherProvider(cipherProvider);
        server.setAuthenticatorSupplier(() -> serverAuth);
        server.setClientAuthenticatorVerifier(this::verify);
        server.setCsExchange(this::csExchange);

        server.clientServerExchange(request, SERVER_NAME, SK_TGS);
    }

    @Test
    public void testServerNameVerifyFail() throws Exception {
        ClientServerExchangeServer server = new ClientServerExchangeServer();
        server = PowerMockito.spy(server);
        server.setCipherProvider(cipherProvider);
        server.setAuthenticatorSupplier(() -> serverAuth);
        server.setClientAuthenticatorVerifier(this::verify);
        server.setCsExchange(this::csExchange);

        try {
            server.clientServerExchange(request, "another server", SK_TGS);
            fail("Must throw ServerVerifyException.");
        } catch (ServerVerifyException e) {
            logger.info(e.getMessage());
        }
        PowerMockito.verifyPrivate(server, Mockito.times(0)).invoke("decrypt", Matchers.anyString(), Matchers.anyString());
    }

    @Test
    public void testDecryptFail() throws Exception {
        ClientServerExchangeServer server = new ClientServerExchangeServer();
        server = PowerMockito.spy(server);
        server.setCipherProvider(cipherProvider);
        server.setAuthenticatorSupplier(() -> serverAuth);
        server.setClientAuthenticatorVerifier(this::verify);
        server.setCsExchange(this::csExchange);

        try {
            server.clientServerExchange(request, SERVER_NAME, "WITH-WRONG-KEY" + SK_TGS);
            fail("Must throw KerberosCryptoException.");
        } catch (KerberosCryptoException e) {
            logger.info(e.getMessage());
        }
        PowerMockito.verifyPrivate(server, Mockito.times(1)).invoke("decrypt", Matchers.anyString(), Matchers.anyString());
        PowerMockito.verifyPrivate(server, Mockito.times(0)).invoke("encrypt", Matchers.anyString(), Matchers.any(Authenticator.class));
    }

    @Test
    public void testVerifyFail() throws Exception {
        ClientServerExchangeServer server = new ClientServerExchangeServer();
        server = PowerMockito.spy(server);
        server.setCipherProvider(cipherProvider);
        server.setAuthenticatorSupplier(() -> serverAuth);
        server.setClientAuthenticatorVerifier((a, b) -> false);
        server.setCsExchange(this::csExchange);

        try {
            server.clientServerExchange(request, SERVER_NAME, SK_TGS);
            fail("Must throw ServerVerifyException.");
        } catch (ServerVerifyException e) {
            logger.info(e.getMessage());
        }
        PowerMockito.verifyPrivate(server, Mockito.times(2)).invoke("decrypt", Matchers.anyString(), Matchers.anyString());
        PowerMockito.verifyPrivate(server, Mockito.times(1)).invoke("mutualAuthentication", Matchers.anyString(), Matchers.anyString());
        // PowerMockito.verifyPrivate(server, Mockito.times(0)).invoke("encrypt", Matchers.anyString(), Matchers.any(Authenticator.class));
    }
}