package com.sample.util;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

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
public class KeyPairUtil {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   *
   */
  private KeyPairUtil() {
  }

  /**
   *
   * @param keyAlgorithm
   * @param bits
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   */
  public static KeyPair createKeyPair(String keyAlgorithm, int bits) throws NoSuchAlgorithmException, NoSuchProviderException {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
      SecureRandom secureRandom = new SecureRandom();
      keyPairGenerator.initialize(bits, secureRandom);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      return keyPair;
  }

  /**
   *
   * @param keyAlgorithm
   * @param bits
   * @param seed
   * @return
   * @throws Exception
   */
  public static KeyPair createKeyPair(String keyAlgorithm, int bits, long seed) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.setSeed(seed);
    keyPairGenerator.initialize(bits, secureRandom);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    return keyPair;
  }

}
