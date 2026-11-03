package ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades de verificación de tokens JWT. Deben coincidir con las del security-service
 * (misma clave secreta Base64 y mismo emisor), ya que el gateway valida tokens emitidos por él.
 *
 * @param secret Clave secreta HMAC en formato Base64 (variable de entorno JWT_SECRET).
 * @param issuer Emisor esperado (claim "iss") de los tokens.
 * @author Logitrack Penguin
 * @version 1.0
 */
@ConfigurationProperties("logitrack.jwt")
public record JwtProperties(String secret, String issuer) {

    public JwtProperties {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("Falta la propiedad logitrack.jwt.secret (JWT_SECRET)");
        }
        if (issuer == null || issuer.isBlank()) {
            issuer = "logitrack-security-service";
        }
    }
}
