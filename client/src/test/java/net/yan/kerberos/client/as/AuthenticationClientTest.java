package net.yan.kerberos.client.as;

import net.yan.kerberos.client.AbstractClientTest;
import net.yan.kerberos.client.core.AuthenticationServiceRequestBuilder;
import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rx.exceptions.Exceptions;

import java.security.GeneralSecurityException;
import java.util.Base64;

import static org.junit.Assert.*;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.crypto.*"})
@PrepareForTest(AuthenticationClient.class)
public class AuthenticationClientTest extends AbstractClientTest {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationClientTest.class);

    AuthenticationServiceRequest request;

    AuthenticationServiceResponse response;

    @Before
    public void setUp() throws Throwable {
        if (null == response) {
            response = new AuthenticationServiceResponse();
            response.setSessionKey("1234567");
            response.setTicketGrantingServerName("44444");
            response.setTicketGrantingTicket("77777");
        }

        if (null == request) {
            request = (new AuthenticationServiceRequestBuilder())
                    .setAddress("localhost")
                    .setClientSettings(clientSettings)
                    .setUsername(clientSettings.getLocalName())
                    .build();
        }
    }

    private AuthenticationServiceRequest getAuthenticationServiceRequest() {
        return request;
    }


    private String resolveRequest(AuthenticationServiceRequest request) {
        assertEquals(this.request, request);
        try {
            return cipherProvider.encryptObject(response, clientSettings.getMasterKey());
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }


    @Test
    public void authenticationServiceExchange() throws Exception {
        AuthenticationClient client = new AuthenticationClient();
        client.setCipherProvider(cipherProvider);
        client.setClientSettings(clientSettings);
        client.setAuthenticationServiceRequestSupplier(this::getAuthenticationServiceRequest);
        client.setAuthenticationServiceRequestFunction(this::resolveRequest);
        client.authenticationServiceExchange().subscribe(response -> {
            assertEquals(this.response, response);
        }, (e) -> {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        });
    }

    @Test
    public void testDefaultCipherProvider() throws Exception {
        AuthenticationClient client = new AuthenticationClient();
        client.setClientSettings(clientSettings);
        client.setAuthenticationServiceRequestSupplier(this::getAuthenticationServiceRequest);
        client.setAuthenticationServiceRequestFunction(this::resolveRequest);
        client.authenticationServiceExchange().subscribe(response -> {
            assertEquals(this.response, response);
        }, e -> {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        });

    }

    @Test
    public void testDecryptedFailed() throws Exception {
        AuthenticationClient client = new AuthenticationClient();
        client = PowerMockito.spy(client);

        client.setCipherProvider(cipherProvider);
        client.setClientSettings(clientSettings);
        client.setAuthenticationServiceRequestSupplier(this::getAuthenticationServiceRequest);
        client.setAuthenticationServiceRequestFunction((s) -> Base64.getEncoder().encodeToString("error string....".getBytes()));
        AuthenticationClient finalClient = client;
        client.authenticationServiceExchange().subscribe(s -> {
            fail("Must throw KerberosException");
        }, e -> {
            log.info("Catch exception: " + e.getMessage());
            GeneralSecurityException ex = (GeneralSecurityException) e.getCause().getCause();
            assertNotNull(ex);
            try {
                PowerMockito.verifyPrivate(finalClient).invoke("decrypt", Matchers.anyString());
            } catch (Exception e1) {
                throw Exceptions.propagate(e1);
            }
        });
    }
}