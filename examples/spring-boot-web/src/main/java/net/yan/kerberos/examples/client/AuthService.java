package net.yan.kerberos.examples.client;

import net.yan.kerberos.client.ClientHelper;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author yanle
 */
@Service("CLIENT")
public class AuthService {

    @Autowired
    private ClientHelper clientHelper;


    public String getSessionKey(String server) throws KerberosException {
        String sessionKey = clientHelper.getServerSessionKey(server);
        clientHelper.handShake(server);
        return sessionKey;
    }
}
