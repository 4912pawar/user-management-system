package com.shree.usermanagement.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Component
public class UserJwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expirationMs}")
    private int jwtExpirationMs;

    // Generate a JWT token
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setId(UUID.randomUUID().toString()) // optional, useful for tracking
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(now())
                .setExpiration(expiryDate())
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Extract username (subject) from token
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // Validate token against a username and expiry
    public boolean validateToken(String token, String username) {
        try {
            final String extractedUsername = extractUsername(token);
            return (extractedUsername.equals(username) && !isTokenExpired(token));
        } catch (Exception e) {
            // log the exception if needed
            return false;
        }
    }

    // Get all claims
    public Claims getAllClaims(String token) {
        return getClaims(token);
    }

    // ======= PRIVATE UTILS =======

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(now());
    }

    private Date now() {
        return new Date();
    }

    private Date expiryDate() {
        return new Date(System.currentTimeMillis() + jwtExpirationMs);
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
}
