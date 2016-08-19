package net.yan.kerberos.client.cs;

import net.yan.kerberos.client.AbstractClientTest;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
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
import rx.exceptions.Exceptions;

import java.security.GeneralSecurityException;
import java.time.Instant;

import static org.junit.Assert.*;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.crypto.*"})
@PrepareForTest(ClientServerExchangeClient.class)
public class ClientServerExchangeClientTest extends AbstractClientTest {

    private static final Logger logger = LoggerFactory.getLogger(ClientServerExchangeServerTest.class);

    String SERVER_NAME = "SERVER_NAME";

    String SERVER_SESSION_KEY = "SERVER_SESSION_KEY_HOME_IT_LONG_ENOUGH";

    String SERVER_TICKET = "SERVER_TICKET";

    Authenticator clientAuth;

    Authenticator serverAuth;

    ClientServerExchangeResponse response;

    @Before
    public void init() {
        if (null == clientAuth) {
            clientAuth = new Authenticator();
            clientAuth.setUsername(clientSettings.getLocalName());
            clientAuth.setAddress("localhost");
            clientAuth.setStartTime(Instant.now().toEpochMilli());
            clientAuth.setLifeTime(clientSettings.getSessionLifeTime());
        }
        if (null == serverAuth) {
            serverAuth = new Authenticator();
            serverAuth.setUsername(SERVER_NAME);
            serverAuth.setAddress("localhost");
            serverAuth.setStartTime(Instant.now().toEpochMilli());
            serverAuth.setLifeTime(clientSettings.getSessionLifeTime());
        }
        if (null == response) {
            response = new ClientServerExchangeResponse();
            try {
                response.setAuthenticator(cipherProvider.encryptObject(serverAuth, SERVER_SESSION_KEY));
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
    }

    ClientServerExchangeResponse exchange(ClientServerExchangeRequest request) {
        assertEquals(SERVER_NAME, request.getServerName());
        assertNotNull(request.getAuthenticator());
        assertEquals(SERVER_TICKET, request.getServerTicket());

        return response;
    }

    @Test
    public void clientServerExchange() throws Exception {
        ClientServerExchangeClient client = new ClientServerExchangeClient();
        client.setCipherProvider(cipherProvider);
        client.setAuthenticatorSupplier(() -> this.clientAuth);
        client.setCsExchange(this::exchange);
        client.setServerAuthenticatorVerifier((serverName, authenticator) -> {
            assertEquals(SERVER_NAME, serverName);
            assertEquals(serverAuth, authenticator);
            return true;
        });

        client.clientServerExchange(SERVER_NAME, SERVER_SESSION_KEY, SERVER_TICKET).subscribe((v) -> {
        }, (e) -> {
            logger.error(e.getLocalizedMessage(), e);
            fail(e.getMessage());
        });
    }

    @Test
    public void testDefaultCipherProvider() throws Exception {
        ClientServerExchangeClient client = new ClientServerExchangeClient();
        client.setAuthenticatorSupplier(() -> this.clientAuth);
        client.setCsExchange(this::exchange);
        client.setServerAuthenticatorVerifier((serverName, authenticator) -> {
            assertEquals(SERVER_NAME, serverName);
            assertEquals(serverAuth, authenticator);
            return true;
        });

        client.clientServerExchange(SERVER_NAME, SERVER_SESSION_KEY, SERVER_TICKET).subscribe((v) -> {
        }, (e) -> {
            logger.error(e.getLocalizedMessage(), e);
            fail(e.getMessage());
        });
    }

    @Test
    public void testVerifyFailed() throws Exception {
        ClientServerExchangeClient client = new ClientServerExchangeClient();
        client.setCipherProvider(cipherProvider);
        client.setAuthenticatorSupplier(() -> this.clientAuth);
        client.setCsExchange(this::exchange);

        AuthenticatorVerifyProvider verifyProvider = PowerMockito.mock(AuthenticatorVerifyProvider.class);
        Mockito.doReturn(Boolean.FALSE).when(verifyProvider).verify(Matchers.anyString(), Matchers.any(Authenticator.class));
        client.setServerAuthenticatorVerifier(verifyProvider);

        client.clientServerExchange(SERVER_NAME, SERVER_SESSION_KEY, SERVER_TICKET)
                .subscribe((v) -> fail("Must throw ServerVerifyException."), (e) -> {
                    assertEquals("Cannot verify server info:" + SERVER_NAME, e.getCause().getMessage());
                    try {
                        Mockito.verify(verifyProvider, Mockito.times(1)).verify(Mockito.anyString(), Mockito.any(Authenticator.class));
                    } catch (ServerVerifyException e1) {
                        throw Exceptions.propagate(e1);
                    }
                });
    }

    @Test
    public void testEncryptFailed() throws Exception {
        ClientServerExchangeClient client = new ClientServerExchangeClient();
        client = PowerMockito.spy(client);

        client.setCipherProvider(cipherProvider);
        client.setAuthenticatorSupplier(() -> this.clientAuth);
        client.setCsExchange(this::exchange);

        AuthenticatorVerifyProvider verifyProvider = PowerMockito.mock(AuthenticatorVerifyProvider.class);
        Mockito.doReturn(Boolean.FALSE).when(verifyProvider).verify(Matchers.anyString(), Matchers.any(Authenticator.class));
        client.setServerAuthenticatorVerifier(verifyProvider);

        ClientServerExchangeClient finalClient = client;
        client.clientServerExchange(SERVER_NAME, "shot", SERVER_TICKET).subscribe((v) -> {
            fail("Must throw KerberosCryptoException.");
        }, (e) -> {
            GeneralSecurityException ex = (GeneralSecurityException) e.getCause().getCause();
            assertNotNull(ex);
            try {
                PowerMockito.verifyPrivate(finalClient, Mockito.times(0)).invoke("mutualAuthentication", Matchers.anyString(), Matchers.anyString(), Matchers.anyString());
            } catch (Exception e1) {
                throw Exceptions.propagate(e1);
            }
        });
    }

    @Test
    public void testIncorrectSessionKey() throws Exception {
        ClientServerExchangeClient client = new ClientServerExchangeClient();
        client = PowerMockito.spy(client);

        client.setCipherProvider(cipherProvider);
        client.setAuthenticatorSupplier(() -> this.clientAuth);
        client.setCsExchange(this::exchange);

        AuthenticatorVerifyProvider verifyProvider = PowerMockito.mock(AuthenticatorVerifyProvider.class);
        PowerMockito.when(verifyProvider.verify(Matchers.anyString(), Matchers.any(Authenticator.class)))
                .thenReturn(false);
        client.setServerAuthenticatorVerifier(verifyProvider);
        ClientServerExchangeClient finalClient = client;
        client.clientServerExchange(SERVER_NAME, "incorrect session key, hope it long enough.", SERVER_TICKET).subscribe((v) -> {
            fail("Must throw ServerVerifyException.");
        }, (e) -> {
            GeneralSecurityException ex = (GeneralSecurityException) e.getCause();
            assertNotNull(ex);

            try {
                PowerMockito.verifyPrivate(finalClient).invoke("mutualAuthentication", Matchers.anyString(), Matchers.anyString(), Matchers.anyString());
            } catch (Exception e1) {
                e1.printStackTrace();
            }
            try {
                Mockito.verify(verifyProvider, Mockito.times(0)).verify(Mockito.anyString(), Mockito.any(Authenticator.class));
            } catch (ServerVerifyException e1) {
                throw Exceptions.propagate(e1);
            }
        });
    }

}