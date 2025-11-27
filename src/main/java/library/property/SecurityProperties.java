package library.property;


import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Set;

@ConfigurationProperties(prefix = "jwt.security")
public class SecurityProperties {

    private String secret;
    private Set<String> requiredClaims;
    private String issuer = "auth-svc";
    private long ttl = 3600_000L;
    private String header = "Authorization";
    private String prefix = "Bearer ";

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public Set<String> getRequiredClaims() {
        return requiredClaims;
    }

    public void setRequiredClaims(Set<String> requiredClaims) {
        this.requiredClaims = requiredClaims;
    }
}
