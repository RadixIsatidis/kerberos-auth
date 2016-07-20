package net.yan.kerberos.as;

import net.yan.kerberos.config.KerberosSettings;
import net.yan.kerberos.core.crypto.CryptoProvider;
import net.yan.kerberos.core.session.SessionGenerator;
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

    private SessionGenerator sessionGenerator;

    public SessionGenerator getSessionGenerator() {
        return sessionGenerator;
    }

    public void setSessionGenerator(SessionGenerator sessionGenerator) {
        this.sessionGenerator = sessionGenerator;
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
        return userDetailsService.loadUserByUsername(request.getUsername());
    }

    public TicketGrantingTicket createTicketGrantingTicket(AuthenticationServiceRequest request)
            throws GeneralSecurityException {
        String sessionKey = sessionGenerator.generate();
        TicketGrantingTicket tgt = new TicketGrantingTicket();
        tgt.setAddress(request.getAddress());
        tgt.setStartTime(Instant.now().toEpochMilli());
        tgt.setLifeTime(kerberosSettings.getSessionLifeTime());
        tgt.setSessionKey(sessionKey);
        tgt.setTicketGrantServer(kerberosSettings.getTicketGrantServer());
        return tgt;
    }

    public String createAuthenticationServiceResponse(
            AuthenticationServiceRequest request,
            UserDetails userDetails
    ) throws GeneralSecurityException, IOException {
        TicketGrantingTicket tgt = createTicketGrantingTicket(request);
        String cryptoTGT = cryptoProvider.encryptObject(tgt, kerberosSettings.getMasterKey());

        AuthenticationServiceResponse response = new AuthenticationServiceResponse();
        response.setSessionKey(tgt.getSessionKey());
        response.setTicketGrantingServer(cryptoTGT);
        response.setTicketGrantingServer(kerberosSettings.getTicketGrantServer());
        return cryptoProvider.encryptObject(response, userDetails.getPassword());
    }


}
