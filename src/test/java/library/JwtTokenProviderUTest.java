package library;

import library.property.SecurityProperties;
import library.exception.InvalidWebTokenException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class JwtTokenProviderUTest {

    private SecurityProperties props;
    private JwtTokenProvider provider;
    private final String secret = "01234567890123456789012345678901";
    private final long ttl = 10000;

    @BeforeEach
    void setup() {
        props = new SecurityProperties();
        props.setSecret(secret);
        props.setIssuer("test-issuer");
        props.setTrustedIssuers(Set.of("test-issuer"));
        props.setTtl(ttl);
        provider = new JwtTokenProvider(props);
    }

    @Test
    void constructor_shouldThrow_ifSecretTooShort() {
        props.setSecret("shortsecret");
        assertThrows(IllegalArgumentException.class, () -> new JwtTokenProvider(props));
    }

    @Test
    void generateToken_shouldThrow_ifMetadataNull() {
        assertThrows(InvalidWebTokenException.class, () -> provider.generateToken(null));
    }

    @Test
    void generateAndParseToken_shouldWork_forUserToken() {
        UUID userId = UUID.randomUUID();
        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("USER"),
                new SimpleGrantedAuthority("ADMIN")
        );
        AuthenticationMetadata metadata = new AuthenticationMetadata(userId, "test@test.com", true, false, authorities);

        String token = provider.generateToken(metadata);
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);

        AuthenticationMetadata parsed = provider.parseToken(token);
        assertEquals(userId, parsed.getUserId());
        assertEquals("test@test.com", parsed.getEmail());
        assertTrue(parsed.isAccountEnabled());
        assertFalse(parsed.isServiceToServiceCall());
        assertTrue(parsed.getAuthorities().contains(new SimpleGrantedAuthority("USER")));
        assertTrue(parsed.getAuthorities().contains(new SimpleGrantedAuthority("ADMIN")));
    }

    @Test
    void generateAndParseToken_shouldWork_forS2SToken() {
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("S2S_CALL"));
        AuthenticationMetadata metadata = new AuthenticationMetadata(null, null, true, true, authorities);

        String token = provider.generateToken(metadata);
        assertNotNull(token);

        AuthenticationMetadata parsed = provider.parseToken(token);
        assertNull(parsed.getUserId());
        assertNull(parsed.getEmail());
        assertTrue(parsed.isAccountEnabled());
        assertTrue(parsed.isServiceToServiceCall());
        assertTrue(parsed.getAuthorities().contains(new SimpleGrantedAuthority("S2S_CALL")));
    }

    @Test
    void parseToken_shouldThrow_ifInvalidToken() {
        assertThrows(InvalidWebTokenException.class, () -> provider.parseToken("invalid.token.value"));
    }

    @Test
    void parseToken_shouldThrow_ifExpired() throws InterruptedException {
        props.setTtl(1); // 1 ms TTL
        provider = new JwtTokenProvider(props);

        AuthenticationMetadata metadata = new AuthenticationMetadata(UUID.randomUUID(), "test@test.com", true, false,
                List.of(new SimpleGrantedAuthority("USER")));
        String token = provider.generateToken(metadata);

        Thread.sleep(5);

        assertThrows(InvalidWebTokenException.class, () -> provider.parseToken(token));
    }

    @Test
    void parseToken_shouldReturnEmptyAuthorities_ifNone() {
        AuthenticationMetadata metadata = new AuthenticationMetadata(UUID.randomUUID(), "test@test.com", true, false, List.of());
        String token = provider.generateToken(metadata);

        AuthenticationMetadata parsed = provider.parseToken(token);
        assertNotNull(parsed.getAuthorities());
        assertTrue(parsed.getAuthorities().isEmpty());
    }
}

