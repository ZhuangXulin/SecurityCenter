/**
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 * You may obtain a copy of the License at

 *  http://www.zhuangxulin.com/licenses/LICENSE-1.0
  
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package com.zhuangxulin.security.rsa;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import sun.misc.BASE64Encoder;

/**
 * @author ZhuangXulin Nov 20, 2015
 */
public class RSAUtil {
	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";

	/**
	 * The method checks if the pair of public and private key ,des encrypt file has been generated.
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public static boolean areKeysPresent(String PRIVATE_KEY_FILE, String PUBLIC_KEY_FILE,String DES_ENCRYPT_FILE) {

		File privateKey = new File(PRIVATE_KEY_FILE);
		File publicKey = new File(PUBLIC_KEY_FILE);
		File desEncryptFile = new File(DES_ENCRYPT_FILE);
		
		if (privateKey.exists() && publicKey.exists() && desEncryptFile.exists()) {
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
	 * Generate key which contains a pair of private and public key using 1024
	 * bytes. Store the set of keys in Prvate.key and Public.key files.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public static void generateKey(String PRIVATE_KEY_FILE, String PUBLIC_KEY_FILE) {
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
			System.out.println("PUBLIC KEY:"+publicKey);
			// Saving the Public key in a file
			// FileOutputStream publicKeyOS = new
			// FileOutputStream(publicKeyFile);
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyOS.write(publicKey.getBytes());
			publicKeyOS.close();

			// Saving the Private key in a file
			String privateKey = (new BASE64Encoder()).encodeBuffer((key.getPrivate().getEncoded()));
			System.out.println("PRIVATE KEY:"+privateKey);
			FileOutputStream privateKeyOS = new FileOutputStream(privateKeyFile);
			privateKeyOS.write(privateKey.getBytes("utf-8"));
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * 获取DES内容，内容使用public key加密
	 * 
	 * @return
	 * @throws IOException
	 */
	public static byte[] getDESValue(String desFilePath) throws IOException {
		File f = new File(desFilePath);
		if (!f.exists()) {
			throw new FileNotFoundException(desFilePath);
		}

		ByteArrayOutputStream bos = new ByteArrayOutputStream((int) f.length());
		BufferedInputStream in = null;
		try {
			in = new BufferedInputStream(new FileInputStream(f));
			int buf_size = 1024;
			byte[] buffer = new byte[buf_size];
			int len = 0;
			while (-1 != (len = in.read(buffer, 0, buf_size))) {
				bos.write(buffer, 0, len);
			}
			return bos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		} finally {
			try {
				in.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			bos.close();
		}
	}

	/**
	 * 保存文本内容
	 * 
	 * @param text
	 */
	public static void saveFile(String desEncryptTempFile,byte[] text) {
		try {
			FileOutputStream outSTr = new FileOutputStream(new File(desEncryptTempFile));
			BufferedOutputStream buff = new BufferedOutputStream(outSTr);
			buff.write(text);
			buff.flush();
			buff.close();
			outSTr.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
