package net.yan.kerberos.examples.client;

import net.yan.kerberos.client.ClientHelper;
import net.yan.kerberos.core.KerberosException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import rx.Observable;

/**
 * @author yanle
 */
@Service("CLIENT")
public class AuthService {

    private final ClientHelper clientHelper;

    @Autowired
    public AuthService(ClientHelper clientHelper) {
        this.clientHelper = clientHelper;
    }


    public Observable<String> getSessionKey(String server) throws KerberosException {
        // String sessionKey = clientHelper.getServerSessionKey(server);
        return clientHelper.handShake(server);
//        return sessionKey;
    }
}
