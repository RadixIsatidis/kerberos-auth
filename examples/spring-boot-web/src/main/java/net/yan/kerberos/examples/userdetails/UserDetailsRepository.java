package net.yan.kerberos.examples.userdetails;

import org.springframework.data.repository.CrudRepository;

/**
 * @author yanle
 */
public interface UserDetailsRepository extends CrudRepository<UserDetailsImpl, String> {

}
