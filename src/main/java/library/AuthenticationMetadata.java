package library;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public final class AuthenticationMetadata implements Serializable, UserDetails {

    private static final long serialVersionUID = 1L;

    private final UUID userId;
    private final String email;
    private final List<GrantedAuthority> authorities;
    private final boolean accountEnabled;
    private final boolean serviceToServiceCall;
    private final Integer tokenVersion;
    private final UUID sessionId;

    public AuthenticationMetadata(UUID userId,
                                  String email,
                                  boolean accountEnabled,
                                  boolean serviceToServiceCall,
                                  List<GrantedAuthority> authorities,
                                  Integer tokenVersion,
                                  UUID sessionId) {
        this.userId = userId;
        this.email = email;
        this.accountEnabled = accountEnabled;
        this.serviceToServiceCall = serviceToServiceCall;
        this.authorities = authorities == null ? List.of() : List.copyOf(authorities);
        this.tokenVersion = tokenVersion;
        this.sessionId = sessionId;
    }

    public UUID getSessionId() {
        return sessionId;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isAccountEnabled();
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountEnabled();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isAccountEnabled();
    }

    @Override
    public boolean isEnabled() {
        return isAccountEnabled();
    }

    public boolean isAccountEnabled() {
        return accountEnabled;
    }
    public boolean isServiceToServiceCall() {
        return serviceToServiceCall;
    }

    public Integer getTokenVersion() {
        return tokenVersion;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) return true;
        if (!(o instanceof AuthenticationMetadata)) return false;
        AuthenticationMetadata that = (AuthenticationMetadata) o;
        return accountEnabled == that.accountEnabled &&
                serviceToServiceCall == that.serviceToServiceCall &&
                Objects.equals(userId, that.userId) &&
                Objects.equals(email, that.email) &&
                Objects.equals(authorities, that.authorities);
    }

    @Override
    public int hashCode() {

        return Objects.hash(userId, email, authorities, accountEnabled, serviceToServiceCall, tokenVersion);
    }

    @Override
    public String toString() {
        return "AuthenticationMetadata{userId=" + userId + ", email=" + email + ", authorities=" + authorities + ", s2s=" + serviceToServiceCall + ", version=" + tokenVersion + ", session=" + sessionId + "}";
    }
}
