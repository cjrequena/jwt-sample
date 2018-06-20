package com.sample.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 *
 * @author cjrequena
 * @version 1.0
 * @see
 * @since JDK1.8
 */
@Log4j2
public class JwtUtil {

  /**
   *
   * @param header
   * @param claims
   * @param id
   * @param issuer
   * @param subject
   * @param secretKey
   * @param expirationMilliseconds
   * @return
   * @throws NoSuchAlgorithmException
   */
  public static String createSignedJwt(Map header, Map claims, SecretKey secretKey, long expirationMilliseconds) throws NoSuchAlgorithmException {

    LocalDateTime localDateTimeNow = LocalDateTime.now();
    Date dateNow = Date.from(localDateTimeNow.atZone(ZoneId.systemDefault()).toInstant());
    long millisecondsNow = localDateTimeNow.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();

    //We will sign our JWT with our ApiKey secret
    //Key signingKey = new SecretKeySpec(DatatypeConverter.parseBase64Binary(secretKey), signatureAlgorithm.getJcaName());

    //Let's set the JWT Claims
    JwtBuilder builder = Jwts.builder()
      .setHeader(header)
      .setClaims(claims)
      .signWith(SignatureAlgorithm.HS256, secretKey);

    //if it has been specified, let's add the expiration
    if (expirationMilliseconds >= 0) {
      builder.setExpiration(new Date(millisecondsNow + expirationMilliseconds));
    }

    //Builds the JWT and serializes it to a compact, URL-safe string
    return builder.compact();
  }

  /**
   *
   * @param jwt
   * @param secretKey
   * @return
   */
  public static Jws<Claims> parseJwt(String jwt, SecretKey secretKey) {
    return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt);
  }

  /**
   *
   * @param secretKey
   * @param jwt
   * @return
   */
  public static boolean validateJwt(String jwt, SecretKey secretKey){
    String signature = parseJwt(jwt, secretKey).getSignature();
    JwsHeader header = parseJwt(jwt, secretKey).getHeader();
    Claims claims = parseJwt(jwt, secretKey).getBody();

    log.info("Signature: {}", signature);
    log.info("Key Id: {}", header.getKeyId());

    log.info("Id: {}", claims.getId());
    log.info("Subject: {}" , claims.getSubject());
    log.info("Issuer: {}" , claims.getIssuer());
    log.info("Expiration: {}" , claims.getExpiration());
    return claims.getSubject()!=null;
  }
}
