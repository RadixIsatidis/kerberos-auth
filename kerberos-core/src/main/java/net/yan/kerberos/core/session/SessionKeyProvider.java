package net.yan.kerberos.core.session;

import java.security.GeneralSecurityException;

public interface SessionKeyProvider {

    String getSessionKey(SessionSettings settings) throws GeneralSecurityException;
}
