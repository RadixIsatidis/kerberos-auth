package net.yan.kerberos.tgs;

import net.yan.kerberos.config.KerberosSettings;
import net.yan.kerberos.core.crypto.CryptoService;
import net.yan.kerberos.core.session.SessionGenerator;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.TicketGrantingServiceRequest;
import net.yan.kerberos.data.TicketGrantingTicket;
import net.yan.kerberos.userdetails.UserDetailsService;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class TicketGrantingService {

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

    private CryptoService cryptoService;

    public CryptoService getCryptoService() {
        return cryptoService;
    }

    public void setCryptoService(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    public TicketGrantingService() {
    }

    public TicketGrantingServiceRequest assignTicketGrantingServiceRequest(TicketGrantingServiceRequest request)
            throws GeneralSecurityException, IOException, ClassNotFoundException {
        String clientTicketGrantingTicketString = request.getClientTicketGrantingTicketString();
        TicketGrantingTicket clientTicketGrantingTicket = cryptoService.decryptObject(clientTicketGrantingTicketString, kerberosSettings.getMasterKey());
        request.setClientTicketGrantingTicket(clientTicketGrantingTicket);

        String serverTicketGrantingTicketString = request.getServerTicketGrantingTicketString();
        TicketGrantingTicket serverTicketGrantingTicket = cryptoService.decryptObject(serverTicketGrantingTicketString, kerberosSettings.getMasterKey());
        request.setServerTicketGrantingTicket(serverTicketGrantingTicket);

        String authString = request.getAuthenticatiorString();
        Authenticator authenticator = cryptoService.decryptObject(authString, clientTicketGrantingTicket.getSessionKey());
        request.setAuthenticator(authenticator);

        return request;
    }

    public boolean verifyUserInfo(TicketGrantingTicket clientTicketGrantingTicket) {
        return false;
    }
}
