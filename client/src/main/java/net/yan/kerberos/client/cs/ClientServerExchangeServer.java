package net.yan.kerberos.client.cs;

import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import net.yan.kerberos.data.ServerTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.function.Supplier;

public class ClientServerExchangeServer {

    private static final Logger log = LoggerFactory.getLogger(ClientServerExchangeServer.class);

    /**
     * Encrypt/Decrypt provider.
     */
    private CipherProvider cipherProvider;

    /**
     * An {@link Authenticator} supplier, can obtain an {@code Authenticator} instance.
     */
    private Supplier<Authenticator> authenticatorSupplier;

    /**
     * Use to verify client authenticator.
     */
    private AuthenticatorVerifyProvider clientAuthenticatorVerifier;


    public CipherProvider getCipherProvider() {
        if (null == cipherProvider)
            cipherProvider = new CipherProvider();
        return cipherProvider;
    }

    public void setCipherProvider(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    public void setAuthenticatorSupplier(Supplier<Authenticator> authenticatorSupplier) {
        this.authenticatorSupplier = authenticatorSupplier;
    }

    public void setClientAuthenticatorVerifier(AuthenticatorVerifyProvider clientAuthenticatorVerifier) {
        this.clientAuthenticatorVerifier = clientAuthenticatorVerifier;
    }

    @SuppressWarnings("unchecked")
    private <T> T decrypt(String key, String secret) throws ClassNotFoundException, GeneralSecurityException {
        return getCipherProvider().decryptObject(secret, key);
    }

    private <T extends Serializable> String encrypt(String key, T secret) throws GeneralSecurityException {
        return getCipherProvider().encryptObject(secret, key);
    }

    private boolean mutualAuthentication(
            String serverSessionKey,
            String secret
    ) throws ServerVerifyException {
        Authenticator authenticator;
        try {
            authenticator = decrypt(serverSessionKey, secret);
            if (log.isDebugEnabled())
                log.debug("Decrypted client Authenticator: " + authenticator);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            throw new ServerVerifyException(e);
        }
        return clientAuthenticatorVerifier.verify(authenticator.getUsername(), authenticator);
    }

    public ClientServerExchangeResponse clientServerExchange(
            ClientServerExchangeRequest request,
            String serverName,
            String rootSessionKey
    ) throws ServerVerifyException, KerberosCryptoException {
        if (log.isDebugEnabled())
            log.debug(String.format("Client Server Exchange: REQUEST:[%s], SERVER_NAME: [%s], SK_TGS: [%s]", request, serverName, rootSessionKey));
        if (log.isDebugEnabled())
            log.debug(String.format("Client Server Exchange: REQUEST:[%s], SERVER_NAME: [%s], SK_TGS: [%s]", request, serverName, rootSessionKey));
        String _serverName = request.getServerName();
        if (!Objects.equals(serverName, _serverName)) {
            throw new ServerVerifyException(String.format("Expects server name %s, actual %s", serverName, _serverName));
        }
        ServerTicket serverTicket;
        try {
            serverTicket = decrypt(rootSessionKey, request.getServerTicket());
            if (log.isDebugEnabled())
                log.debug("Decrypted ServerTicket: " + serverTicket);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            throw new KerberosCryptoException(e);
        }
        String clientSessionKey = serverTicket.getSessionKey();

        if (!mutualAuthentication(clientSessionKey, request.getAuthenticator())) {
            throw new ServerVerifyException("Verify client info failed.");
        }

        // 组Authenticator
        Authenticator authenticator = authenticatorSupplier.get();
        if (log.isDebugEnabled())
            log.debug("Create server Authenticator: " + authenticator);
        String encryptAuth;
        try {
            encryptAuth = encrypt(clientSessionKey, authenticator);
            if (log.isDebugEnabled())
                log.debug("Encrypted server Authenticator: " + authenticator);
        } catch (GeneralSecurityException e) {
            throw new KerberosCryptoException(e);
        }
        ClientServerExchangeResponse response = new ClientServerExchangeResponse();
        response.setAuthenticator(encryptAuth);
        if (log.isDebugEnabled())
            log.debug("Create ClientServerExchangeResponse: " + response);
        return response;
    }
}
