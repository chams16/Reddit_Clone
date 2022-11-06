package com.example.reddit.security;
import com.example.reddit.exception.SpringRedditException;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.swing.*;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.time.Instant;

@Service
public class JwtProvider {

    private KeyStore keyStore;
    //private final JwtEncoder jwtEncoder;

//    @Value("${jwt.expiration.time}")
//    private Long jwtExpirationInMillis;

    @PostConstruct
    public void init(){
        try{
            keyStore = KeyStore.getInstance("JKS");
            InputStream resourceAsStream = getClass().getResourceAsStream("/springblog.jks");
            keyStore.load(resourceAsStream,"secret".toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String generateToken(Authentication authentication) {
        User principal = (User) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(principal.getUsername())
                .signWith(getPrivateKey())
                .compact();
    }

//    public String generateTokenWithUserName(String username) {
//        JwtClaimsSet claims = JwtClaimsSet.builder()
//                .issuer("self")
//                .issuedAt(Instant.now())
//                .expiresAt(Instant.now().plusMillis(jwtExpirationInMillis))
//                .subject(username)
//                .claim("scope", "ROLE_USER")
//                .build();
//        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
//    }

    public PrivateKey getPrivateKey() {
        try{
            return (PrivateKey) keyStore.getKey("springblog","secret".toCharArray());
        }catch (Exception e){
            throw new SpringRedditException("exception while retrieving public key");
        }
    }
}
