package net.yan.kerberos.kdc.tgc;

import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.core.session.SessionKeyProvider;
import net.yan.kerberos.data.*;
import net.yan.kerberos.kdc.config.KerberosSettings;
import net.yan.kerberos.kdc.userdetails.UserDetails;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;

import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.time.Instant;

/**
 * Class that providing ticket granting service.
 */
public class TicketGrantingService {

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

    private AuthenticatorVerifyProvider authenticatorVerifyProvider;

    public AuthenticatorVerifyProvider getAuthenticatorVerifyProvider() {
        if (null == authenticatorVerifyProvider)
            authenticatorVerifyProvider = new DefaultAuthenticatorVerifyProvider();
        return authenticatorVerifyProvider;
    }

    public void setAuthenticatorVerifyProvider(AuthenticatorVerifyProvider authenticatorVerifyProvider) {
        this.authenticatorVerifyProvider = authenticatorVerifyProvider;
    }

    public TicketGrantingService() {
    }

    /**
     * Load user details using username.
     *
     * @param username username.
     * @return user details
     * @see UserDetailsService#loadUserByUsername(String)
     */
    public UserDetails loadUserByUsername(String username) {
        return getUserDetailsService().loadUserByUsername(username);
    }

    /**
     * Decrypt ticket granting service request.
     * <p>
     * Decrypt server/client ticket granting ticket using KDC master key.<br>
     * Decrypt client authenticator using session witch within the decrypted client ticket granting ticket that belong to this session.
     *
     * @param request ticket granting service request.
     * @return a {@link TicketGrantingServiceRequest} that containing decrypted data.
     * @throws GeneralSecurityException any security exception.
     * @throws ClassNotFoundException   class not found.
     * @see CipherProvider#encryptObject(Serializable, String)
     */
    public TicketGrantingServiceRequest assignTicketGrantingServiceRequest(TicketGrantingServiceRequest request)
            throws GeneralSecurityException, ClassNotFoundException {
        String clientTicketGrantingTicketString = request.getClientTicketGrantingTicketString();
        TicketGrantingTicket clientTicketGrantingTicket = getCipherProvider().decryptObject(clientTicketGrantingTicketString, getKerberosSettings().getMasterKey());
        request.setClientTicketGrantingTicket(clientTicketGrantingTicket);

        String serverTicketGrantingTicketString = request.getServerTicketGrantingTicketString();
        TicketGrantingTicket serverTicketGrantingTicket = getCipherProvider().decryptObject(serverTicketGrantingTicketString, getKerberosSettings().getMasterKey());
        request.setServerTicketGrantingTicket(serverTicketGrantingTicket);

        String authString = request.getAuthenticatorString();
        Authenticator authenticator = getCipherProvider().decryptObject(authString, clientTicketGrantingTicket.getSessionKey());
        request.setAuthenticator(authenticator);

        return request;
    }

    /**
     * Verify user info.
     *
     * @param ticketGrantingTicket client ticket granting ticket.
     * @param authenticator        client authenticator
     * @return {@code true} if verify success, {@code false} else.
     */
    public boolean verifyAuthenticator(TicketGrantingTicket ticketGrantingTicket, Authenticator authenticator) {
        return authenticatorVerifyProvider.verify(ticketGrantingTicket, authenticator);
    }

    /**
     * Generate a client-server session key.
     *
     * @return session key string.
     * @throws GeneralSecurityException any security exception.
     */
    public String generateServerSessionKey() throws GeneralSecurityException {
        return getSessionKeyProvider().generate();
    }

    /**
     * Create a server ticket using ticket granting service request.
     *
     *
     * @param request
     * @return
     * @throws GeneralSecurityException
     */
    public ServerTicket createServerTicket(TicketGrantingServiceRequest request) throws GeneralSecurityException {
        ServerTicket serverTicket = new ServerTicket();
        TicketGrantingTicket clientTicketGrantingTicket = request.getClientTicketGrantingTicket();
        TicketGrantingTicket serverTicketGrantingTicket = request.getServerTicketGrantingTicket();
        Authenticator authenticator = request.getAuthenticator();
        assert (null != clientTicketGrantingTicket);
        assert (null != serverTicketGrantingTicket);
        assert (null != authenticator);

        String serverSessionKey = generateServerSessionKey();

        UserDetails server = loadUserByUsername(serverTicketGrantingTicket.getUsername());
        serverTicket.setUsername(server.getUsername());
        serverTicket.setAddress(serverTicketGrantingTicket.getAddress());
        serverTicket.setStartTime(Instant.now().toEpochMilli());
        serverTicket.setLifeTime(getKerberosSettings().getSessionLifeTime());
        serverTicket.setSessionKey(serverSessionKey);

        return serverTicket;
    }

    public TicketGrantingServiceResponse createTicketGrantingServiceResponse(TicketGrantingServiceRequest request)
            throws GeneralSecurityException, IOException {
        String clientTGSSessionKey = request.getClientTicketGrantingTicket().getSessionKey();
        assert (null != clientTGSSessionKey);
        String serverTGSSessionKey = request.getServerTicketGrantingTicket().getSessionKey();
        assert (null != serverTGSSessionKey);
        ServerTicket serverTicket = createServerTicket(request);

        String serverSessionKey = serverTicket.getSessionKey();
        String encryptServerSessionKey = getCipherProvider().encryptString(serverSessionKey, getCipherProvider().generateKey(clientTGSSessionKey));

        String encryptServerTicket = getCipherProvider().encryptObject(serverTicket, serverTGSSessionKey);

        TicketGrantingServiceResponse response = new TicketGrantingServiceResponse();
        response.setServerSessionKey(encryptServerSessionKey);
        response.setServerTicket(encryptServerTicket);
        return response;
    }
}
