package net.yan.kerberos.kdc.as;

import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.core.session.SessionKeyProvider;
import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.TicketGrantingTicket;
import net.yan.kerberos.kdc.config.KerberosSettings;
import net.yan.kerberos.kdc.userdetails.UserDetails;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.time.Instant;

/**
 * Class defines API to providing authentication service.
 */
public class AuthenticationService {

    private UserDetailsService userDetailsService;

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    private SessionKeyProvider sessionKeyProvider;

    public SessionKeyProvider getSessionKeyProvider() {
        return sessionKeyProvider;
    }

    public void setSessionKeyProvider(SessionKeyProvider sessionKeyProvider) {
        this.sessionKeyProvider = sessionKeyProvider;
    }

    private KerberosSettings kerberosSettings;

    public KerberosSettings getKerberosSettings() {
        return kerberosSettings;
    }

    public void setKerberosSettings(KerberosSettings kerberosSettings) {
        this.kerberosSettings = kerberosSettings;
    }

    private CipherProvider cipherProvider;

    public CipherProvider getCipherProvider() {
        return cipherProvider;
    }

    public void setCipherProvider(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    public AuthenticationService() {
    }

    /**
     * Load user details using {@link AuthenticationServiceRequest}
     *
     * @param request authentication service request.
     * @return user detail.
     * @see UserDetailsService#loadUserByUsername(String)
     */
    public UserDetails loadUserByUsername(AuthenticationServiceRequest request) {
        return getUserDetailsService().loadUserByUsername(request.getUsername());
    }

    /**
     * Accept a {@link AuthenticationServiceRequest} and create a {@link TicketGrantingTicket} witch containing
     * a session key.
     *
     * @param request a request containing client info.
     * @return a ticket granting ticket witch containing a session key.
     * @throws GeneralSecurityException any security exception.
     */
    public TicketGrantingTicket createTicketGrantingTicket(AuthenticationServiceRequest request)
            throws GeneralSecurityException {
        String sessionKey = getSessionKeyProvider().generate();
        TicketGrantingTicket tgt = new TicketGrantingTicket();
        tgt.setUsername(request.getUsername());
        tgt.setAddress(request.getAddress());
        tgt.setStartTime(Instant.now().toEpochMilli());
        tgt.setLifeTime(getKerberosSettings().getSessionLifeTime());
        tgt.setSessionKey(sessionKey);
        tgt.setTicketGrantServer(getKerberosSettings().getTicketGrantingServerName());
        return tgt;
    }

    /**
     * Accept a {@link AuthenticationServiceRequest} and create a encrypted {@link AuthenticationServiceResponse} string, witch containing
     * a encrypted {@link TicketGrantingTicket} string, ticket granting server address and session key belong to this session.
     *
     * @param request     a request containing client info.
     * @param userDetails user detail from {@link #loadUserByUsername(AuthenticationServiceRequest)}
     * @return a encrypted {@link AuthenticationServiceResponse} string
     * @throws GeneralSecurityException any security exception.
     * @see #encryptTicketGrantingTicket(TicketGrantingTicket)
     * @see #loadUserByUsername(AuthenticationServiceRequest)
     * @see #createTicketGrantingTicket(AuthenticationServiceRequest)
     */
    public String createAuthenticationServiceResponse(
            AuthenticationServiceRequest request,
            UserDetails userDetails
    ) throws GeneralSecurityException {
        return createAuthenticationServiceResponse(createTicketGrantingTicket(request), userDetails);
    }

    /**
     * Encrypt ticket granting ticket using KDC master key.
     *
     * @param tgt a ticket granting ticket
     * @return a encrypted {@link TicketGrantingTicket} string
     * @throws GeneralSecurityException any security exception.
     * @see KerberosSettings#getMasterKey()
     * @see CipherProvider#encryptObject(Serializable, String)
     */
    public String encryptTicketGrantingTicket(TicketGrantingTicket tgt) throws GeneralSecurityException {
        return getCipherProvider().encryptObject(tgt, getKerberosSettings().getMasterKey());
    }

    /**
     * Accept a {@link AuthenticationServiceRequest} and {@link UserDetails} to create a encrypted
     * {@link AuthenticationServiceResponse} string, witch containing a encrypted {@link TicketGrantingTicket} string,
     * ticket granting server address and session key belong to this session.
     *
     * @param tgt         ticket granting ticket.
     * @param userDetails user details.
     * @return a encrypted {@link AuthenticationServiceResponse} string
     * @throws GeneralSecurityException any security exception.
     * @see #createTicketGrantingTicket(AuthenticationServiceRequest)
     * @see #loadUserByUsername(AuthenticationServiceRequest)
     */
    public String createAuthenticationServiceResponse(
            TicketGrantingTicket tgt,
            UserDetails userDetails
    ) throws GeneralSecurityException {
        String cryptoTGT = encryptTicketGrantingTicket(tgt);

        AuthenticationServiceResponse response = new AuthenticationServiceResponse();
        response.setSessionKey(tgt.getSessionKey());
        response.setTicketGrantingTicket(cryptoTGT);
        response.setTicketGrantingServerName(getKerberosSettings().getTicketGrantingServerName());
        return getCipherProvider().encryptObject(response, userDetails.getPassword());
    }
}
