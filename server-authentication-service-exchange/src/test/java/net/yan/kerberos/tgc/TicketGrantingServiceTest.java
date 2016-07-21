package net.yan.kerberos.tgc;

import net.yan.kerberos.config.DefaultSettingsTest;
import net.yan.kerberos.data.*;
import net.yan.kerberos.userdetails.UserDetails;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;

import static org.junit.Assert.*;

/**
 * Created by yanle on 2016/7/21.
 */
public class TicketGrantingServiceTest extends DefaultSettingsTest {

    private TicketGrantingService tgs;

    private AuthenticationServiceRequest serviceRequest;

    private AuthenticationServiceRequest clientRequest;

    private TicketGrantingTicket clientTicketGrantingTicket;

    private TicketGrantingTicket serverTicketGrantingTicket;

    private TicketGrantingServiceRequest ticketGrantingServiceRequest;

    private Authenticator authenticator;

    @Before
    public void setUp() throws Exception {
        super.setUp();

        if (null == tgs) {
            tgs = new TicketGrantingService();
            tgs.setUserDetailsService(userDetailsService);
            tgs.setSessionKeyProvider(sessionKeyProvider);
            tgs.setKerberosSettings(kerberosSettings);
            tgs.setCryptoProvider(cryptoProvider);
        }

        if (null == serviceRequest) {
            serviceRequest = new AuthenticationServiceRequest();
            serviceRequest.setUsername("app server");
            serviceRequest.setAddress("127.0.0.1");
            serviceRequest.setStartTime(Instant.now().toEpochMilli());
            serviceRequest.setLifeTime(30 * 60 * 1000L);
        }

        if (null == clientRequest) {
            clientRequest = new AuthenticationServiceRequest();
            clientRequest.setUsername("app user");
            clientRequest.setAddress("127.0.0.1");
            clientRequest.setStartTime(Instant.now().toEpochMilli());
            clientRequest.setLifeTime(30 * 60 * 1000L);
        }

        if (null == clientTicketGrantingTicket) {
            clientTicketGrantingTicket = authenticationService.createTicketGrantingTicket(clientRequest);
        }
        if (null == serverTicketGrantingTicket) {
            serverTicketGrantingTicket = authenticationService.createTicketGrantingTicket(serviceRequest);
        }
        if (null == authenticator) {
            authenticator = new Authenticator();
            authenticator.setUsername(clientRequest.getUsername());
            authenticator.setAddress(clientRequest.getAddress());
            authenticator.setLifeTime(Instant.now().toEpochMilli());
            authenticator.setLifeTime(30 * 60 * 1000L);
        }

        if (null == ticketGrantingServiceRequest) {
            ticketGrantingServiceRequest = new TicketGrantingServiceRequest();
            String client = authenticationService.encryptTicketGrantingTicket(clientTicketGrantingTicket);
            ticketGrantingServiceRequest.setClientTicketGrantingTicketString(client);
            String server = authenticationService.encryptTicketGrantingTicket(serverTicketGrantingTicket);
            ticketGrantingServiceRequest.setServerTicketGrantingTicketString(server);

            ticketGrantingServiceRequest.setAuthenticatiorString(cryptoProvider.encryptObject(authenticator, clientTicketGrantingTicket.getSessionKey()));
        }

    }

    @Test
    public void loadUserByUsername() throws Exception {
        String usrname = "username";
        UserDetails userDetails = tgs.loadUserByUsername(usrname);
        assertNotNull(userDetails);
        assertEquals(usrname, userDetails.getUsername());
    }

    @Test
    public void assignTicketGrantingServiceRequest() throws Exception {
        TicketGrantingServiceRequest request = tgs.assignTicketGrantingServiceRequest(ticketGrantingServiceRequest);
        assertNotNull(request.getClientTicketGrantingTicket());
        assertEquals(clientTicketGrantingTicket, request.getClientTicketGrantingTicket());
        assertNotNull(request.getServerTicketGrantingTicket());
        assertEquals(serverTicketGrantingTicket, request.getServerTicketGrantingTicket());
        assertNotNull(request.getAuthenticator());
        assertEquals(authenticator, request.getAuthenticator());
    }

    @Test
    public void verifyUserInfo() throws Exception {
        assertTrue(tgs.verifyUserInfo(clientTicketGrantingTicket, authenticator));
    }

    @Test
    public void createTicketGrantingServiceResponse() throws Exception {
        TicketGrantingServiceRequest request = tgs.assignTicketGrantingServiceRequest(ticketGrantingServiceRequest);
        TicketGrantingServiceResponse response = tgs.createTicketGrantingServiceResponse(request);
        assertNotNull(response);
        System.out.println(response);
    }

}