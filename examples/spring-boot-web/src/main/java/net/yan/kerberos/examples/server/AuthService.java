package net.yan.kerberos.examples.server;

import net.yan.kerberos.client.ServerHelper;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author yanle
 */
@Service("SERVER")
public class AuthService {

    private final ServerHelper serverHelper;

    @Autowired
    public AuthService(ServerHelper serverHelper) {
        this.serverHelper = serverHelper;
    }


    public String getTGT() throws KerberosException {
        return serverHelper.getRootTicket();
    }

    public ClientServerExchangeResponse auth(ClientServerExchangeRequest request) throws KerberosException {
        return serverHelper.handShake(request);
    }
}
