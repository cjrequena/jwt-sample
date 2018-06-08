package com.sample.util;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
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
public class EncryptionUtil {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   *
   */
  private EncryptionUtil() {
  }

  /**
   * <p>
   * Creates an asymmetric  key pair.
   * </p>
   * <br>
   * Asymmetric keys are used for asymmetric encryption algorithms. Asymmetric encryption algorithms use one key for encryption, and another for decryption. The public key - private
   * key encryption algorithms are examples of asymmetric encryption algorithms.
   *
   * @param keyAlgorithm
   * @param keyBitSize
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   */
  public static KeyPair createKeyPair(String keyAlgorithm, int keyBitSize) throws NoSuchAlgorithmException, NoSuchProviderException {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
      SecureRandom secureRandom = new SecureRandom();
      keyPairGenerator.initialize(keyBitSize, secureRandom);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      return keyPair;
  }

  /**
   * <p>
   * Creates an asymmetric  key pair.
   * </p>
   * <br>
   * Asymmetric keys are used for asymmetric encryption algorithms. Asymmetric encryption algorithms use one key for encryption, and another for decryption. The public key - private
   * key encryption algorithms are examples of asymmetric encryption algorithms.
   *
   * @param keyAlgorithm
   * @param keyBitSize
   * @param seed
   * @return
   * @throws Exception
   */
  public static KeyPair createKeyPair(String keyAlgorithm, int keyBitSize, long seed) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.setSeed(seed);
    keyPairGenerator.initialize(keyBitSize, secureRandom);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    return keyPair;
  }

  /**
   * <p>
   * Creates a secret (symmetric) key.
   * </p>
   * <br>
   * Symmetric keys are used for symmetric encryption algorithms. Symmetric encryption algorithms use the same key for encryption and decryption.
   *
   *
   * @param keyAlgorithm
   * @param keyBitSize
   * @return
   * @throws NoSuchAlgorithmException
   */
  public static SecretKey createSecretKey(String keyAlgorithm, int keyBitSize) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
    SecureRandom secureRandom = new SecureRandom();
    keyGenerator.init(keyBitSize, secureRandom);
    return keyGenerator.generateKey();
  }

  /**
   *
   * @param data
   * @param key
   * @return
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public static String encrypt(String data,  SecretKey key, String keyAlgorithm)
    throws InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    Cipher cipher = Cipher.getInstance(keyAlgorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key);
    AlgorithmParameters params = cipher.getParameters();
    byte[] encryptedData  = cipher.doFinal(data.getBytes("UTF-8"));
    return Base64.toBase64String(encryptedData);
  }

  /**
   *
   * @param data
   * @param key
   * @return
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public static String decrypt(String data,  SecretKey key, String keyAlgorithm)
    throws InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    Cipher cipher = Cipher.getInstance(keyAlgorithm);
    cipher.init(Cipher.DECRYPT_MODE, key);
    AlgorithmParameters params = cipher.getParameters();
    byte[] decodedData = Base64.decode(data.getBytes("UTF-8"));
    byte[] decryptedData   = cipher.doFinal(decodedData);
    return new String(decryptedData);
  }

}
