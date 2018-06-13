package com.sample.util;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Base64;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.List;

import static com.sample.util.EncryptionUtil.createKeyPair;
import static com.sample.util.Jose4jUtil.createRsaJsonWebKey;
import static org.junit.Assert.assertEquals;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 *
 *
 *
 * @author cjrequena
 * @version 1.0
 * @see
 * @since JDK1.8
 */
@Log4j2
public class Jose4jUtilTest {

  @Test
  public void createSignedJwtCase1Test() throws JoseException, InvalidJwtException {
    RsaJsonWebKey rsaJsonWebKey = createRsaJsonWebKey();
    log.debug("private key: {}", Base64.toBase64String(rsaJsonWebKey.getRsaPrivateKey().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(rsaJsonWebKey.getRsaPublicKey().getEncoded()));

    JwtClaims claims = new JwtClaims();
    claims.setIssuer("Issuer");  // who creates the token and signs it
    claims.setAudience("Audience"); // to whom the token is intended to be sent
    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
    claims.setGeneratedJwtId(); // a unique identifier for the token
    claims.setIssuedAtToNow();  // when the token was issued/created (now)
    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
    claims.setSubject("subject"); // the subject/principal is whom the token is about
    claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array
    String jwt = Jose4jUtil.createSignedJwt(claims, rsaJsonWebKey, "k1");

    JwtConsumer jwtConsumer= Jose4jUtil.getConsumer(rsaJsonWebKey);
    JwtClaims claimsConsumed = jwtConsumer.processToClaims(jwt);
    assertEquals(claims.toJson(), claimsConsumed.toJson());
    assertEquals(jwt, jwtConsumer.process(jwt).getJwt());

  }

  @Test
  public void createSignedJwtCase2Test() throws JoseException, InvalidJwtException, NoSuchProviderException, NoSuchAlgorithmException {
    // Generate a 1024-bit RSA key pair
    KeyPair keyPair = createKeyPair("RSA", 2048);
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));

    JwtClaims claims = new JwtClaims();
    claims.setIssuer("Issuer");  // who creates the token and signs it
    claims.setAudience("Audience"); // to whom the token is intended to be sent
    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
    claims.setGeneratedJwtId(); // a unique identifier for the token
    claims.setIssuedAtToNow();  // when the token was issued/created (now)
    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
    claims.setSubject("subject"); // the subject/principal is whom the token is about
    claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array
    String jwt = Jose4jUtil.createSignedJwt(claims, keyPair.getPrivate(), "k1");

    JwtConsumer jwtConsumer= Jose4jUtil.getConsumer(keyPair.getPublic());
    JwtClaims claimsConsumed = jwtConsumer.processToClaims(jwt);
    assertEquals(claims.toJson(), claimsConsumed.toJson());
    assertEquals(jwt, jwtConsumer.process(jwt).getJwt());

  }

}
