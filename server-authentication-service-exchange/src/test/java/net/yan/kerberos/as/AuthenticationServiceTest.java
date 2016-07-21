package net.yan.kerberos.as;

import net.yan.kerberos.config.DefaultSettingsTest;
import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.TicketGrantingTicket;
import net.yan.kerberos.userdetails.UserDetails;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;

import static org.junit.Assert.*;

/**
 * Created by yanle on 2016/7/21.
 */
public class AuthenticationServiceTest extends DefaultSettingsTest {

    private AuthenticationServiceRequest request;

    @Before
    public void setUp() throws Exception {
        super.setUp();

        if (null == request) {
            request = new AuthenticationServiceRequest();
            request.setUsername("user name");
            request.setAddress("127.0.0.1");
            request.setStartTime(Instant.now().toEpochMilli());
            request.setLifeTime(30 * 60 * 1000L);
        }
    }

    @Test
    public void loadUserByUsername() {
        UserDetails userDetails = authenticationService.loadUserByUsername(request);
        assertNotNull(userDetails);
        assertEquals(request.getUsername(), userDetails.getUsername());
    }

    @Test
    public void createTicketGrantingTicket() throws Exception {
        TicketGrantingTicket ticket = authenticationService.createTicketGrantingTicket(request);
        assertNotNull(ticket.getSessionKey());
        assertEquals(request.getUsername(), ticket.getUsername());
        assertEquals(request.getAddress(), ticket.getAddress());
        assertNotEquals(request, ticket);
    }

    @Test
    public void createAuthenticationServiceResponse() throws Exception {
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());

        TicketGrantingTicket ticket = authenticationService.createTicketGrantingTicket(request);
        String str1 = authenticationService.createAuthenticationServiceResponse(request, userDetails);
        assertNotNull(str1);

        String str2 = authenticationService.createAuthenticationServiceResponse(ticket, userDetails);
        AuthenticationServiceResponse response = cryptoProvider.decryptObject(str2, userDetails.getPassword());
        assertEquals(ticket.getSessionKey(), response.getSessionKey());
        TicketGrantingTicket ticket1 = cryptoProvider.decryptObject(response.getTicketGrantingTicket(), kerberosSettings.getMasterKey());
        assertEquals(ticket, ticket1);
    }

}