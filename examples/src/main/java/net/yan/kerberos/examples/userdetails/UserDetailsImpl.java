package net.yan.kerberos.examples.userdetails;

import net.yan.kerberos.kdc.userdetails.UserDetails;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * @author yanle
 */
@Entity(name = "users")
@Table(name = "users")
public class UserDetailsImpl implements UserDetails {

    private static final long serialVersionUID = -2343545683309218827L;

    @Id
    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
