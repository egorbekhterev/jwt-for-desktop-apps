package com.sandboxspringsecurity.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.sandboxspringsecurity.entity.Token;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@AllArgsConstructor
@Slf4j
public class RefreshTokenJweStringDeserializer implements Function<String, Token> {

    private JWEDecrypter jweDecrypter;

    @Override
    public Token apply(String s) {
        try {
            var encryptedJWT = EncryptedJWT.parse(s);
            encryptedJWT.decrypt(this.jweDecrypter);
            var claimsSet = encryptedJWT.getJWTClaimsSet();
            return new Token(UUID.fromString(claimsSet.getJWTID()), claimsSet.getSubject(),
                    claimsSet.getStringListClaim("authorities"), claimsSet.getIssueTime().toInstant(),
                    claimsSet.getExpirationTime().toInstant());
        } catch (ParseException | JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
