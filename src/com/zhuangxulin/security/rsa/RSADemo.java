package com.zhuangxulin.security.rsa;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;

public class RSADemo {
	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";

	/**
	 * String to hold the name of the private key file.
	 */
	public static final String PRIVATE_KEY_FILE = "key/zhuangxulin@ancun.com-pvk.pem";

	/**
	 * String to hold name of the public key file.
	 */
	public static final String PUBLIC_KEY_FILE = "key/zhuangxulin@ancun.com-puk.pem";

	/**
	 * Generate key which contains a pair of private and public key using 1024
	 * bytes. Store the set of keys in Prvate.key and Public.key files.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public static void generateKey() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(1024);
			final KeyPair key = keyGen.generateKeyPair();

			File privateKeyFile = new File(PRIVATE_KEY_FILE);
			File publicKeyFile = new File(PUBLIC_KEY_FILE);

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();
			String publicKey = (new BASE64Encoder()).encodeBuffer((key.getPublic().getEncoded()));
			System.out.println(publicKey);
			// Saving the Public key in a file
			// FileOutputStream publicKeyOS = new
			// FileOutputStream(publicKeyFile);
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyOS.write(publicKey.getBytes());
			publicKeyOS.close();

			// Saving the Private key in a file
			String privateKey = (new BASE64Encoder()).encodeBuffer((key.getPrivate().getEncoded()));
			System.out.println(privateKey);
			FileOutputStream privateKeyOS = new FileOutputStream(privateKeyFile);
			privateKeyOS.write(privateKey.getBytes("utf-8"));
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * The method checks if the pair of public and private key has been
	 * generated.
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public static boolean areKeysPresent() {

		File privateKey = new File(PRIVATE_KEY_FILE);
		File publicKey = new File(PUBLIC_KEY_FILE);

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}

	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public static byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The private key
	 * @return plain text
	 * @throws java.lang.Exception
	 */
	public static String decrypt(byte[] text, PrivateKey key) {
		byte[] dectyptedText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			dectyptedText = cipher.doFinal(text);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return new String(dectyptedText);
	}

	/**
	 * 获取DES内容，内容使用public key加密
	 * 
	 * @return
	 * @throws IOException 
	 */
	public static byte[] getDESValue(String desFilePath) throws IOException {
		File f = new File(desFilePath);  
        if(!f.exists()){  
            throw new FileNotFoundException(desFilePath);  
        }  
  
        ByteArrayOutputStream bos = new ByteArrayOutputStream((int)f.length());  
        BufferedInputStream in = null;  
        try{  
            in = new BufferedInputStream(new FileInputStream(f));  
            int buf_size = 1024;  
            byte[] buffer = new byte[buf_size];  
            int len = 0;  
            while(-1 != (len = in.read(buffer,0,buf_size))){  
                bos.write(buffer,0,len);  
            }  
            System.out.println(bos.toByteArray());
            return bos.toByteArray();  
        }catch (IOException e) {  
            e.printStackTrace();  
            throw e;  
        }finally{  
            try{  
                in.close();  
            }catch (IOException e) {  
                e.printStackTrace();  
            }  
            bos.close();  
        }
	}

	/**
	 * Test the EncryptionUtil
	 */
	public static void main(String[] args) {
		try {
			// Check if the pair of keys are present else generate those.
			if (!areKeysPresent()) {
				// Method generates a pair of keys using the RSA algorithm and
				// stores it
				// in their respective files
				generateKey();
			}

			final String originalText = "Text to be encrypted,Hello World. ";
			// Encrypt the string using the public key
			File pukFile = new File(PUBLIC_KEY_FILE);
			BufferedReader readerPuk = new BufferedReader(new FileReader(pukFile));
			String tempStringPuk = null;
			String strPuk = "";
			// 一次读入一行，直到读入null为文件结束
			while ((tempStringPuk = readerPuk.readLine()) != null) {
				strPuk += tempStringPuk;
			}
			String PUKBEGIN = "-----BEGIN PUBLIC KEY-----";
			String PUKEND = "-----END PUBLIC KEY-----";
			String publicStr = new String(strPuk);
			if (publicStr.contains(PUKBEGIN) && publicStr.contains(PUKEND)) {
				publicStr = publicStr.substring(PUKBEGIN.length(), publicStr.lastIndexOf(PUKEND));
			}
			// public key 转换成为base64
			byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(publicStr);
			X509EncodedKeySpec specPuk = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactoryPuk = KeyFactory.getInstance(ALGORITHM);
			PublicKey pukey = keyFactoryPuk.generatePublic(specPuk);
			final byte[] cipherText = encrypt(originalText, pukey);

			// Decrypt the cipher text using the private key.
			File filePrv = new File(PRIVATE_KEY_FILE);
			BufferedReader readerPrv = new BufferedReader(new FileReader(filePrv));
			String tempStringPrv = null;
			String strPrv = "";
			// 一次读入一行，直到读入null为文件结束
			while ((tempStringPrv = readerPrv.readLine()) != null) {
				strPrv += tempStringPrv;
			}
			String PRVBEGIN = "-----BEGIN RSA PRIVATE KEY-----";
			String PRVEND = "-----END RSA PRIVATE KEY-----";
			String privateStr = new String(strPrv);
			if (privateStr.contains(PRVBEGIN) && privateStr.contains(PRVEND)) {
				privateStr = privateStr.substring(PRVBEGIN.length(), privateStr.lastIndexOf(PRVEND));
			}
			

			// private key 转换成为base64
			byte[] keyBytesPrv = (new BASE64Decoder()).decodeBuffer(privateStr);
			java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			PKCS8EncodedKeySpec specPrv = new PKCS8EncodedKeySpec(keyBytesPrv);
			KeyFactory keyFactoryPrv = KeyFactory.getInstance(ALGORITHM);
			PrivateKey prkey = keyFactoryPrv.generatePrivate(specPrv);
			//final String plainText = decrypt(cipherText, prkey);
			final String plainText = decrypt(RSADemo.getDESValue("key/zhuangxulin@ancun.com-des_key.pem"), prkey);
			

			// Printing the Original, Encrypted and Decrypted Text
			System.out.println("Original: " + originalText);
			System.out.println("Encrypted: " + cipherText.toString());
			System.out.println("Decrypted: " + plainText);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
