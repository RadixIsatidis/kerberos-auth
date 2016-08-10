package net.yan.kerberos.examples.kdc;

import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceResponse;
import net.yan.kerberos.kdc.as.AuthenticationService;
import net.yan.kerberos.kdc.tgc.TicketGrantingService;
import net.yan.kerberos.kdc.userdetails.UserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * @author yanle
 */
@Service
public class KDCService {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private TicketGrantingService ticketGrantingService;


    public String resolveAuthenticationServiceRequest(AuthenticationServiceRequest request)
            throws GeneralSecurityException {
        UserDetails userDetails = authenticationService.loadUserDetails(request);
        return authenticationService.createAuthenticationServiceResponse(request, userDetails);
    }

    public TicketGrantingServiceResponse resolveServerTicket(TicketGrantingServiceRequest request)
            throws GeneralSecurityException, IOException, ClassNotFoundException {
        request = ticketGrantingService.assignTicketGrantingServiceRequest(request);
        return ticketGrantingService.createTicketGrantingServiceResponse(request);
    }

}
