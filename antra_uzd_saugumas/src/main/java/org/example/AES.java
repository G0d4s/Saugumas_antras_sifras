package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AES {


    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION_ECB = "AES/ECB/PKCS5Padding";
    private static final String TRANSFORMATION_CBC = "AES/CBC/PKCS5Padding";
    private static final String TRANSFORMATION_CFB = "AES/CFB/PKCS5Padding";
    private static final String TRANSFORMATION_OFB = "AES/OFB/PKCS5Padding";
    private static final String TRANSFORMATION_CTR = "AES/CTR/NoPadding";

    public static String encryptECB(String plaintext, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptECB(String ciphertext, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_ECB);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, "UTF-8");
    }

    public static String encryptCBC(String plaintext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptCBC(String ciphertext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CBC);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, "UTF-8");
    }

    public static String encryptCFB(String plaintext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CFB);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptCFB(String ciphertext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CFB);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, "UTF-8");
    }

    public static String encryptOFB(String plaintext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_OFB);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptOFB(String ciphertext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_OFB);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, "UTF-8");
    }

    public static String encryptCTR(String plaintext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CTR);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptCTR(String ciphertext, String secretKey, String iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CTR);
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, "UTF-8");
    }

}
