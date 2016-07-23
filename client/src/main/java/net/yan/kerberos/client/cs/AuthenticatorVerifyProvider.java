package net.yan.kerberos.client.cs;

import net.yan.kerberos.client.ClientHelper;
import net.yan.kerberos.data.Authenticator;

/**
 * Class that defines API used by {@link ClientHelper}
 */
public interface AuthenticatorVerifyProvider {

    boolean verify(String name, Authenticator authenticator) throws ServerVerifyException;
}
