package com.sample.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.*;

@Log4j2
public class JwtUtilTest {



  @Test
  public void createSignedJwt() throws NoSuchAlgorithmException {

    SecretKey secretKey = EncryptionUtil.createSecretKey("AES", 128);

    Map claimsMap = new HashMap();
    claimsMap.put("test", "test");
    claimsMap.put("scope","[admin, read, write]");

    Map headersMap = new HashMap();
    headersMap.put("header1","header1");

    String jwt = JwtUtil.createSignedJwt(headersMap, claimsMap,  secretKey, 10000);
    Jws<Claims> jws = JwtUtil.parseJwt(jwt, secretKey);
    String signature = jws.getSignature();
    JwsHeader header = jws.getHeader();
    Claims claims = jws.getBody();

    log.info("secretKey: {}", Base64.toBase64String(secretKey.getEncoded()));
    log.info("signature: {}", signature);
    log.info("Expiration: {}" , claims.getExpiration());
    log.info("headers: {}", header);
    log.info("claims: {}", claims);


  }

  @Test
  public void parseJwt() {
  }

  @Test
  public void validateJwt() {
  }
}
