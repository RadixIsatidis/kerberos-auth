package net.yan.kerberos.tgs;

import net.yan.kerberos.config.KerberosSettings;
import net.yan.kerberos.core.crypto.CryptoProvider;
import net.yan.kerberos.core.session.SessionGenerator;
import net.yan.kerberos.data.*;
import net.yan.kerberos.userdetails.UserDetails;
import net.yan.kerberos.userdetails.UserDetailsService;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Objects;

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

    private CryptoProvider cryptoProvider;

    public CryptoProvider getCryptoProvider() {
        return cryptoProvider;
    }

    public void setCryptoProvider(CryptoProvider cryptoProvider) {
        this.cryptoProvider = cryptoProvider;
    }

    public TicketGrantingService() {
    }

    public UserDetails loadUserByUsername(String username) {
        return userDetailsService.loadUserByUsername(username);
    }

    public TicketGrantingServiceRequest assignTicketGrantingServiceRequest(TicketGrantingServiceRequest request)
            throws GeneralSecurityException, IOException, ClassNotFoundException {
        String clientTicketGrantingTicketString = request.getClientTicketGrantingTicketString();
        TicketGrantingTicket clientTicketGrantingTicket = cryptoProvider.decryptObject(clientTicketGrantingTicketString, kerberosSettings.getMasterKey());
        request.setClientTicketGrantingTicket(clientTicketGrantingTicket);

        String serverTicketGrantingTicketString = request.getServerTicketGrantingTicketString();
        TicketGrantingTicket serverTicketGrantingTicket = cryptoProvider.decryptObject(serverTicketGrantingTicketString, kerberosSettings.getMasterKey());
        request.setServerTicketGrantingTicket(serverTicketGrantingTicket);

        String authString = request.getAuthenticatiorString();
        Authenticator authenticator = cryptoProvider.decryptObject(authString, clientTicketGrantingTicket.getSessionKey());
        request.setAuthenticator(authenticator);

        return request;
    }

    public boolean verifyUserInfo(TicketGrantingTicket clientTicketGrantingTicket, Authenticator authenticator) {
        long t = clientTicketGrantingTicket.getStartTime() + clientTicketGrantingTicket.getLifeTime();
        Instant now = Instant.now();
        Instant after = Instant.ofEpochMilli(t);
        // TODO  verify user info
        return now.isBefore(after)
                && Objects.equals(clientTicketGrantingTicket.getUsername(), authenticator.getUsername());
    }

    public String createServerSessionKey() throws GeneralSecurityException {
        return sessionGenerator.generate();
    }

    public ServerTicket createServerTicket(TicketGrantingServiceRequest request) throws GeneralSecurityException {
        ServerTicket serverTicket = new ServerTicket();
        TicketGrantingTicket clientTicketGrantingTicket = request.getClientTicketGrantingTicket();
        TicketGrantingTicket serverTicketGrantingTicket = request.getServerTicketGrantingTicket();
        Authenticator authenticator = request.getAuthenticator();
        assert (null != clientTicketGrantingTicket);
        assert (null != serverTicketGrantingTicket);
        assert (null != authenticator);

        String serverSessionKey = createServerSessionKey();

        UserDetails server = loadUserByUsername(serverTicketGrantingTicket.getUsername());
        serverTicket.setUsername(server.getUsername());
        serverTicket.setAddress(serverTicketGrantingTicket.getAddress());
        serverTicket.setStartTime(Instant.now().toEpochMilli());
        serverTicket.setLifeTime(kerberosSettings.getSessionLifeTime());
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
        String encryptServerSessionKey = cryptoProvider.encryptString(serverSessionKey, cryptoProvider.generateKey(clientTGSSessionKey));

        String encryptServerTicket = cryptoProvider.encryptObject(serverTicket, serverTGSSessionKey);

        TicketGrantingServiceResponse response = new TicketGrantingServiceResponse();
        response.setServerSessionKey(encryptServerSessionKey);
        response.setServerTicket(encryptServerTicket);
        return response;
    }
}
