package net.yan.kerberos.client.cs;

import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.GeneralSecurityException;
import java.util.function.Function;
import java.util.function.Supplier;

public class ClientServerExchangeClient {

    private static final Log log = LogFactory.getLog(ClientServerExchangeClient.class);

    /**
     * Encrypt/Decrypt provider.
     */
    private CipherProvider cipherProvider;

    /**
     * An {@link Authenticator} supplier, can obtain an {@code Authenticator} instance.
     */
    private Supplier<Authenticator> authenticatorSupplier;

    /**
     * A {@link ClientServerExchangeRequest} handler, providing the capability of obtaining
     * an {@link ClientServerExchangeResponse} by using an {@code ClientServerExchangeRequest} instance.
     */
    private Function<ClientServerExchangeRequest, ClientServerExchangeResponse> csExchange;

    private AuthenticatorVerifyProvider serverAuthenticatorVerifier;


    public CipherProvider getCipherProvider() {
        if (null == cipherProvider)
            cipherProvider = new CipherProvider();
        return cipherProvider;
    }

    public void setCipherProvider(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    private Authenticator decrypt(String key, String secret) throws ClassNotFoundException, GeneralSecurityException {
        return getCipherProvider().decryptObject(secret, key);
    }

    private boolean mutualAuthentication(
            String serverName,
            String serverSessionKey,
            String secret
    ) throws ServerVerifyException {
        Authenticator authenticator;
        try {
            authenticator = decrypt(secret, serverSessionKey);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            throw new ServerVerifyException(e);
        }
        return serverAuthenticatorVerifier.verify(serverName, authenticator);
    }

    public void clientServerExchange(
            String serverName,
            String serverSessionKey,
            String serverTicket
    ) throws KerberosException {
        // 组Authenticator
        Authenticator authenticator = authenticatorSupplier.get();

        String encryptedAuth;
        try {
            encryptedAuth = getCipherProvider().encryptObject(authenticator, serverSessionKey);
        } catch (GeneralSecurityException e) {
            log.error(e.getMessage());
            throw new KerberosException(e);
        }

        ClientServerExchangeRequest request = new ClientServerExchangeRequest();
        request.setServerName(serverName);
        request.setServerTicket(serverTicket);
        request.setAuthenticator(encryptedAuth);

        ClientServerExchangeResponse response = csExchange.apply(request);
        if (!mutualAuthentication(serverName, serverSessionKey, response.getAuthenticator())) {
            throw new ServerVerifyException("Cannot verify server info:" + serverName);
        }
    }
}
