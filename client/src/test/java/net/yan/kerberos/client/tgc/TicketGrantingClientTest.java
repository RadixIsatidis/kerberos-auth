package net.yan.kerberos.client.tgc;

import net.yan.kerberos.client.AbstractClientTest;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.TicketGrantingServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceResponse;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.crypto.*"})
@PrepareForTest(TicketGrantingClient.class)
public class TicketGrantingClientTest extends AbstractClientTest {

    private static final Logger log = LoggerFactory.getLogger(TicketGrantingClientTest.class);

    String rootSessionKey = "root session key, hope it long enough..........";

    String TGT_CLIENT = "TGT_CLIENT";

    String TGT_SERVER = "TGT_SERVER";

    TicketGrantingServiceResponseWrapper wrapper = new TicketGrantingServiceResponseWrapper() {{
        setServerTicket("server ticket");
        setServerSessionKey("server session key");
    }};

    Authenticator authenticator;

    TicketGrantingServiceRequest request;

    private TicketGrantingServiceResponse response(TicketGrantingServiceRequest request) {
        assertEquals(this.request, request);
        TicketGrantingServiceResponse response = new TicketGrantingServiceResponse();
        try {
            response.setServerSessionKey(cipherProvider.encryptString(wrapper.getServerSessionKey(), cipherProvider.generateKey(rootSessionKey)));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
        response.setServerTicket(wrapper.getServerTicket());
        return response;
    }

    @Before
    public void init() {
        if (null == authenticator) {
            authenticator = new Authenticator();
            authenticator.setStartTime(Instant.now().toEpochMilli());
            authenticator.setLifeTime(clientSettings.getSessionLifeTime());
            authenticator.setAddress("localhost");
            authenticator.setUsername(clientSettings.getLocalName());
        }
        if (null == request) {
            request = new TicketGrantingServiceRequest();
            try {
                request.setAuthenticatorString(cipherProvider.encryptObject(authenticator, rootSessionKey));
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
            request.setClientTicketGrantingTicketString(TGT_CLIENT);
            request.setServerTicketGrantingTicketString(TGT_SERVER);
        }
    }

    @Test
    public void ticketGrantingServiceExchange() throws Exception {
        TicketGrantingClient client = new TicketGrantingClient();
        client.setCipherProvider(cipherProvider);
        client.setAuthenticatorSupplier(() -> authenticator);
        client.setTicketGrantingServiceRequestFunction(this::response);

        client.ticketGrantingServiceExchange(TGT_SERVER, rootSessionKey, TGT_CLIENT).subscribe(wrapper -> assertEquals(this.wrapper, wrapper), (e) -> {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        });
    }

    @Test
    public void testDefaultCipherProvider() throws Exception {
        CipherProvider cipherProvider = new CipherProvider();
        PowerMockito.whenNew(CipherProvider.class).withAnyArguments().thenReturn(cipherProvider);

        TicketGrantingClient client = new TicketGrantingClient();
        client.setAuthenticatorSupplier(() -> authenticator);
        client.setTicketGrantingServiceRequestFunction(this::response);

        client.ticketGrantingServiceExchange(TGT_SERVER, rootSessionKey, TGT_CLIENT).subscribe(wrapper -> {
            assertEquals(this.wrapper, wrapper);
            assertEquals(cipherProvider, client.getCipherProvider());
        }, (e) -> {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        });
    }

    @Test
    public void testEncryptFailed() throws Exception {
        TicketGrantingClient client = new TicketGrantingClient();
        client = PowerMockito.spy(client);

        client.setAuthenticatorSupplier(() -> authenticator);
        client.setTicketGrantingServiceRequestFunction(this::response);

        TicketGrantingClient finalClient = client;
        client.ticketGrantingServiceExchange(TGT_SERVER, "shot....", TGT_CLIENT).subscribe(wrapper -> {
            fail("Must throw KerberosCryptoException.");
        }, (e) -> {
            log.info("Catch exception: " + e.getMessage());

            try {
                PowerMockito.verifyPrivate(finalClient).invoke("encrypt", Matchers.any(Authenticator.class), Matchers.anyString());
            } catch (Exception e1) {
                throw Exceptions.propagate(e1);
            }
            try {
                PowerMockito.verifyPrivate(finalClient, Mockito.times(0)).invoke("decrypt", Matchers.any(Authenticator.class), Matchers.anyString());
            } catch (Exception e1) {
                throw Exceptions.propagate(e1);
            }
        });
    }

    @Test
    public void testDecryptFailed() throws Exception {
        TicketGrantingClient client = new TicketGrantingClient();
        client = PowerMockito.spy(client);

        client.setAuthenticatorSupplier(() -> authenticator);
        client.setTicketGrantingServiceRequestFunction((TicketGrantingServiceRequest request) -> {
            assertEquals(this.request, request);
            TicketGrantingServiceResponse response = new TicketGrantingServiceResponse();
            try {
                response.setServerSessionKey(cipherProvider.encryptString(wrapper.getServerSessionKey(), cipherProvider.generateKey("long long long long long long key.")));
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
            response.setServerTicket(wrapper.getServerTicket());
            return response;
        });

        TicketGrantingClient finalClient = client;
        client.ticketGrantingServiceExchange(TGT_SERVER, rootSessionKey, TGT_CLIENT).subscribe(e -> fail("Must throw KerberosCryptoException."), e -> {
            log.info("Catch exception: " + e.getMessage());

            try {
                PowerMockito.verifyPrivate(finalClient).invoke("encrypt", Matchers.any(Authenticator.class), Matchers.anyString());
            } catch (Exception e1) {
                throw Exceptions.propagate(e1);
            }
            try {
                PowerMockito.verifyPrivate(finalClient).invoke("decrypt", Matchers.any(Authenticator.class), Matchers.anyString());
            } catch (Exception e1) {
                throw Exceptions.propagate(e1);
            }
        });
    }

}