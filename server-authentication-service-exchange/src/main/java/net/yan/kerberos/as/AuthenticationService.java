package net.yan.kerberos.as;

import net.yan.kerberos.config.KerberosSettings;
import net.yan.kerberos.core.crypto.CryptoProvider;
import net.yan.kerberos.core.session.SessionKeyProvider;
import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.TicketGrantingTicket;
import net.yan.kerberos.userdetails.UserDetails;
import net.yan.kerberos.userdetails.UserDetailsService;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;

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

    private CryptoProvider cryptoProvider;

    public CryptoProvider getCryptoProvider() {
        return cryptoProvider;
    }

    public void setCryptoProvider(CryptoProvider cryptoProvider) {
        this.cryptoProvider = cryptoProvider;
    }

    public AuthenticationService() {
    }

    public UserDetails loadUserByUsername(AuthenticationServiceRequest request) {
        return getUserDetailsService().loadUserByUsername(request.getUsername());
    }

    public TicketGrantingTicket createTicketGrantingTicket(AuthenticationServiceRequest request)
            throws GeneralSecurityException {
        String sessionKey = getSessionKeyProvider().generate();
        TicketGrantingTicket tgt = new TicketGrantingTicket();
        tgt.setUsername(request.getUsername());
        tgt.setAddress(request.getAddress());
        tgt.setStartTime(Instant.now().toEpochMilli());
        tgt.setLifeTime(getKerberosSettings().getSessionLifeTime());
        tgt.setSessionKey(sessionKey);
        tgt.setTicketGrantServer(getKerberosSettings().getTicketGrantServerName());
        return tgt;
    }

    public String createAuthenticationServiceResponse(
            AuthenticationServiceRequest request,
            UserDetails userDetails
    ) throws GeneralSecurityException, IOException {
        return createAuthenticationServiceResponse(createTicketGrantingTicket(request), userDetails);
    }

    public String encryptTicketGrantingTicket(TicketGrantingTicket tgt) throws GeneralSecurityException, IOException {
        return getCryptoProvider().encryptObject(tgt, getKerberosSettings().getMasterKey());
    }

    public String createAuthenticationServiceResponse(
            TicketGrantingTicket tgt,
            UserDetails userDetails
    ) throws GeneralSecurityException, IOException {
        String cryptoTGT = encryptTicketGrantingTicket(tgt);

        AuthenticationServiceResponse response = new AuthenticationServiceResponse();
        response.setSessionKey(tgt.getSessionKey());
        response.setTicketGrantingTicket(cryptoTGT);
        response.setTicketGrantingServerName(getKerberosSettings().getTicketGrantServerName());
        return getCryptoProvider().encryptObject(response, userDetails.getPassword());
    }
}
