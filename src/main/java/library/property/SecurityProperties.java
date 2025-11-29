package library.property;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Set;

@Validated
@ConfigurationProperties(prefix = "jwt.security")
public class SecurityProperties {

    @NotBlank(message = "jwt.security.secret must be defined.")
    private String secret;
    private String issuer = "unknown";
    @NotEmpty(message = "jwt.security.trustedIssuers must be defined and contain at least one value.")
    private Set<String> trustedIssuers;
    private long ttl;

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

    public Set<String> getTrustedIssuers() {
        return trustedIssuers;
    }

    public void setTrustedIssuers(Set<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }
}
