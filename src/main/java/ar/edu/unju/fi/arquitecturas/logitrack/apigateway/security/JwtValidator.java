package ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Valida tokens JWT emitidos por el security-service: verifica la firma HMAC, la vigencia y el emisor,
 * replicando la lógica de {@code JwtUtil} del security-service (misma decodificación Base64 de la clave).
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Slf4j
@Component
public class JwtValidator {

    private final SecretKey signingKey;
    private final String issuer;

    public JwtValidator(JwtProperties properties) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(properties.secret()));
        this.issuer = properties.issuer();
        log.info("Validador JWT inicializado (emisor esperado: '{}')", issuer);
    }

    /**
     * Verifica el token y extrae la identidad del usuario.
     *
     * @param token Token JWT compacto (sin el prefijo "Bearer ").
     * @return La identidad contenida en el token.
     * @throws io.jsonwebtoken.JwtException Si la firma no coincide, el token está mal formado,
     *                                      expiró o fue emitido por otro emisor.
     * @throws IllegalArgumentException     Si el token es nulo o vacío.
     */
    public AuthenticatedUser validate(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Object userId = claims.get("userId");
        Object dni = claims.get("dni");
        AuthenticatedUser user = new AuthenticatedUser(
                userId != null ? userId.toString() : null,
                claims.getSubject(),
                extractRoles(claims.get("roles")),
                dni != null ? dni.toString() : null);
        log.debug("Token válido para '{}' con roles {}", user.username(), user.roles());
        return user;
    }

    private static Set<String> extractRoles(Object rawRoles) {
        Set<String> roles = new LinkedHashSet<>();
        if (rawRoles instanceof Collection<?> collection) {
            collection.stream().filter(r -> r != null).map(Object::toString).forEach(roles::add);
        } else if (rawRoles instanceof String s && !s.isBlank()) {
            for (String role : s.split(",")) {
                roles.add(role.trim());
            }
        }
        return Set.copyOf(roles);
    }
}
