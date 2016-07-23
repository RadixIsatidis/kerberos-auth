package net.yan.kerberos.client.cs;

import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.function.Function;
import java.util.function.Supplier;

public class ClientServerExchangeClient {

    private static final Logger log = LoggerFactory.getLogger(ClientServerExchangeClient.class);

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

    public void setAuthenticatorSupplier(Supplier<Authenticator> authenticatorSupplier) {
        this.authenticatorSupplier = authenticatorSupplier;
    }

    public void setCsExchange(Function<ClientServerExchangeRequest, ClientServerExchangeResponse> csExchange) {
        this.csExchange = csExchange;
    }

    public void setServerAuthenticatorVerifier(AuthenticatorVerifyProvider serverAuthenticatorVerifier) {
        this.serverAuthenticatorVerifier = serverAuthenticatorVerifier;
    }

    private Authenticator decrypt(String key, String secret) throws ClassNotFoundException, GeneralSecurityException {
        return getCipherProvider().decryptObject(secret, key);
    }

    private boolean mutualAuthentication(
            String serverName,
            String serverSessionKey,
            String secret
    ) throws ServerVerifyException {
        if (log.isDebugEnabled())
            log.debug("Receive server [" + serverName + "] Authenticator: " + secret);
        Authenticator authenticator;
        try {
            authenticator = decrypt(serverSessionKey, secret);
            if (log.isDebugEnabled())
                log.debug("Decrypted server Authenticator: " + authenticator);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            throw new ServerVerifyException(e);
        }
        boolean result = serverAuthenticatorVerifier.verify(serverName, authenticator);
        if (log.isDebugEnabled())
            log.debug("Verify server authenticator " + result);
        return result;
    }

    public void clientServerExchange(
            String serverName,
            String serverSessionKey,
            String serverTicket
    ) throws KerberosCryptoException, ServerVerifyException {
        log.info(String.format("Client Server Exchange: SERVER: [%s], SK_SERVER: [%s], ST: [%s]",
                serverName, serverSessionKey, serverTicket));
        // 组Authenticator
        Authenticator authenticator = authenticatorSupplier.get();
        if (log.isDebugEnabled())
            log.debug("Create client Authenticator: " + authenticator);

        String encryptedAuth;
        try {
            encryptedAuth = getCipherProvider().encryptObject(authenticator, serverSessionKey);
            if (log.isDebugEnabled())
                log.debug("Encrypted client authenticator: " + encryptedAuth);
        } catch (GeneralSecurityException e) {
            throw new KerberosCryptoException(e);
        }

        ClientServerExchangeRequest request = new ClientServerExchangeRequest();
        request.setServerName(serverName);
        request.setServerTicket(serverTicket);
        request.setAuthenticator(encryptedAuth);
        if (log.isDebugEnabled())
            log.debug("Create ClientServerExchangeRequest:" + request);

        ClientServerExchangeResponse response = csExchange.apply(request);
        if (log.isDebugEnabled())
            log.debug("Receive ClientServerExchangeResponse: " + response);
        if (!mutualAuthentication(serverName, serverSessionKey, response.getAuthenticator())) {
            throw new ServerVerifyException("Cannot verify server info:" + serverName);
        }
    }
}
