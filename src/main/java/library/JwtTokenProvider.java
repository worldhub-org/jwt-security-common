package library;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import library.exception.InvalidWebTokenException;
import library.property.SecurityProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

public class JwtTokenProvider {

    protected static final String DELIMITER = ":";
    protected static final String WORLD_HUB_ISSUER_PREFIX = "world-hub" + DELIMITER;
    protected static final String BE_SERVICE_SUBJECT = "BE_SERVICE";
    protected static final String USER_ID_CLAIM_KEY = "userId";
    protected static final String EMAIL_CLAIM_KEY = "email";
    protected static final String ACCOUNT_ENABLED_CLAIM_KEY = "accountEnabled";
    protected static final String AUTHORITIES_CLAIM_KEY = "authorities";
    protected static final String TOKEN_TYPE_CLAIM_KEY = "token_type";
    private static final int MIN_HMAC_KEY_BYTES = 32;
    private static final Set<String> REQUIRED_CLAIMS = Set.of("sub", "iss", "token_type");

    private final Key hmacKey;
    private final SecurityProperties props;

    public JwtTokenProvider(SecurityProperties props) {

        this.props = props;
        byte[] keyBytes = props.getSecret().getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < MIN_HMAC_KEY_BYTES) {
            throw new IllegalArgumentException("jwt.security.secret is too short; require at least " + MIN_HMAC_KEY_BYTES + " bytes for HS256");
        }
        this.hmacKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(AuthenticationMetadata metadata) {

        if (metadata == null) {
            throw new InvalidWebTokenException("Authentication principle object can't be null.");
        }

        long now = System.currentTimeMillis();
        String subject = metadata.getUserId() == null && metadata.getEmail() == null
                ? BE_SERVICE_SUBJECT
                : metadata.getUserId() + DELIMITER + metadata.getEmail();

        long ttl = props.getTtl();
        if (ttl <= 0) {
            throw new IllegalArgumentException("props.ttl must be positive");
        }

        JwtBuilder tokenBuilder = Jwts.builder()
                .setClaims(buildClaims(metadata))
                .setSubject(subject)
                .setIssuer(WORLD_HUB_ISSUER_PREFIX + props.getIssuer())
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttl))
                .signWith(hmacKey, SignatureAlgorithm.HS256);

        return tokenBuilder.compact();
    }

    public AuthenticationMetadata parseToken(String token) {

        try {

            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(hmacKey)
                    .build()
                    .parseClaimsJws(token);

            String iss = claims.getBody().getIssuer();
            if (!iss.contains(WORLD_HUB_ISSUER_PREFIX)) {
                throw new InvalidWebTokenException("Token rejected: Invalid issuer '" + iss + "'.");
            }

            iss = iss.replace(WORLD_HUB_ISSUER_PREFIX, "");
            if (!props.getTrustedIssuers().contains(iss)) {
                throw new InvalidWebTokenException("Token rejected: Untrusted issuer '" + iss + "'.");
            }

            boolean tokenExpired = isTokenExpired(claims.getBody().getExpiration());
            if (tokenExpired) {
                throw new InvalidWebTokenException("JWT is expired.");
            }

            long numberOfRequiredClaims = REQUIRED_CLAIMS.size();
            long numberOfRequiredClaimsInToken = claims.getBody().entrySet().stream()
                    .filter(e -> REQUIRED_CLAIMS.contains(e.getKey()))
                    .count();
            if (numberOfRequiredClaimsInToken != numberOfRequiredClaims) {
                throw new InvalidWebTokenException("JWT is has missing required claim.");
            }

            String rawUserId = claims.getBody().get(USER_ID_CLAIM_KEY, String.class);
            UUID userId = rawUserId == null ? null : UUID.fromString(rawUserId);
            String email = claims.getBody().get(EMAIL_CLAIM_KEY, String.class);
            Boolean accountEnabled = claims.getBody().get(ACCOUNT_ENABLED_CLAIM_KEY, Boolean.class);
            TokenType tokenType = TokenType.valueOf(claims.getBody().get(TOKEN_TYPE_CLAIM_KEY, String.class));
            List<?> rawAuth = claims.getBody().get(AUTHORITIES_CLAIM_KEY, List.class);
            List<GrantedAuthority> authorities = rawAuth == null
                    ? Collections.emptyList()
                    : rawAuth.stream()
                    .map(Object::toString)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toUnmodifiableList());

            return new AuthenticationMetadata(userId, email, accountEnabled, tokenType == TokenType.S2S, authorities);
        } catch (Exception e) {
            throw new InvalidWebTokenException("JWT is not valid and can't be parsed. JWT=[%s]".formatted(token), e);
        }
    }

    private boolean isTokenExpired(Date expiration) {

        return expiration.before(new Date());
    }

    private Map<String, Object> buildClaims(AuthenticationMetadata metadata) {

        Map<String, Object> claims = new HashMap<>();

        if (metadata.getUserId() != null) {
            claims.put(USER_ID_CLAIM_KEY, metadata.getUserId().toString());
        }
        if (metadata.getEmail() != null) {
            claims.put(EMAIL_CLAIM_KEY, metadata.getEmail());
        }

        claims.put(ACCOUNT_ENABLED_CLAIM_KEY, metadata.isAccountEnabled());

        Collection<? extends GrantedAuthority> authorities = metadata.getAuthorities();
        claims.put(AUTHORITIES_CLAIM_KEY, authorities.stream().map(GrantedAuthority::getAuthority).toList());

        if (metadata.isServiceToServiceCall()) {
            claims.put(TOKEN_TYPE_CLAIM_KEY, TokenType.S2S);
        } else {
            claims.put(TOKEN_TYPE_CLAIM_KEY, TokenType.USER);
        }

        return claims;
    }

    private enum TokenType {
        S2S,
        USER
    }
}
