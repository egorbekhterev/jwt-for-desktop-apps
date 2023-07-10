package com.sandboxspringsecurity.serializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sandboxspringsecurity.entity.Token;
import lombok.AllArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.sql.Date;
import java.util.function.Function;

@Slf4j
@AllArgsConstructor
@Setter
public class AccessTokenJwsStringSerializer implements Function<Token, String> {

    private final JWSSigner jwsSigner;

    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner) {
        this.jwsSigner = jwsSigner;
    }

    @Override
    public String apply(Token token) {
        var jwsHeader = new JWSHeader.Builder(this.jwsAlgorithm)
                .keyID(token.id().toString())
                .build();
        var jwsClaimsSet = new JWTClaimsSet.Builder()
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();
        var signedJWT = new SignedJWT(jwsHeader, jwsClaimsSet);
        try {
            signedJWT.sign(this.jwsSigner);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
