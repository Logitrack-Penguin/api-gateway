package ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security;

import java.util.Set;

/**
 * Identidad extraída de un token JWT válido.
 *
 * @param userId   Identificador del usuario (claim "userId").
 * @param username Nombre de usuario (claim "sub").
 * @param roles    Roles del usuario (claim "roles"): ADMIN, CLIENTE y/o REPARTIDOR.
 * @author Logitrack Penguin
 * @version 1.0
 */
public record AuthenticatedUser(String userId, String username, Set<String> roles) {
}
