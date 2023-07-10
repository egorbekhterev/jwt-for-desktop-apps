package com.sandboxspringsecurity.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.sandboxspringsecurity.entity.Token;
import lombok.AllArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@AllArgsConstructor
@Setter
@Slf4j
public class AccessTokenJwsStringDeserializer implements Function<String, Token> {

    private final JWSVerifier jwsVerifier;

    @Override
    public Token apply(String string) {
        try {
            var signedJWT = SignedJWT.parse(string);
            if (signedJWT.verify(this.jwsVerifier)) {
                var claimsSet = signedJWT.getJWTClaimsSet();
                return new Token(UUID.fromString(claimsSet.getJWTID()), claimsSet.getSubject(),
                        claimsSet.getStringListClaim("authorities"), claimsSet.getIssueTime().toInstant(),
                        claimsSet.getExpirationTime().toInstant());
            }
        } catch (ParseException | JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
