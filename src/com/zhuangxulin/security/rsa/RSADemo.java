
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

/**
 * @author ZhuangXulin
 * Nov 17, 2015
 */
public class RSADemo {
	

	/**
	 * String to hold the name of the private key file.
	 */
	public static final String PRIVATE_KEY_FILE = "key/zhuangxulin-pvk.pem";

	/**
	 * String to hold name of the public key file.
	 */
	public static final String PUBLIC_KEY_FILE = "key/zhuangxulin-puk.pem";
	
	/**
	 * originalText内容加密后保存的文件
	 */
	public static final String DES_ENCRYPT_TEMP_FILE = "key/des-encrypt_temp.pem";
	
	/**
	 * 获取到得des encrypt文件，这个文件是在其他地方通过public key加密
	 */
	public static final String DES_ENCRYPT_FILE = "key/zhuangxulin-des_key.pem";
	/**
	 * Test the EncryptionUtil
	 */
	public static void main(String[] args) {
		try {
			// Check if the pair of keys are present else generate those.
			if (!RSAUtil.areKeysPresent(PRIVATE_KEY_FILE,PUBLIC_KEY_FILE,DES_ENCRYPT_FILE)) {
				// Method generates a pair of keys using the RSA algorithm and
				// stores it
				// in their respective files
				RSAUtil.generateKey(PRIVATE_KEY_FILE,PUBLIC_KEY_FILE);
				System.out.println("DES encrypt File is not exist,please checked it.");
			}
			//此编码是des encrypt file中进行解码后的内容
			final String originalText = "6ae2c40c909de52f15cd3f9a39e37467";
			// Encrypt the string using the public key
			File pukFile = new File(PUBLIC_KEY_FILE);
			BufferedReader readerPuk = new BufferedReader(new FileReader(pukFile));
			String tempStringPuk = null;
			String strPuk = "";
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
			KeyFactory keyFactoryPuk = KeyFactory.getInstance(RSAUtil.ALGORITHM);
			PublicKey pukey = keyFactoryPuk.generatePublic(specPuk);
			final byte[] cipherText = RSAUtil.encrypt(originalText, pukey);
			//保存des加密后的内容到文件
			RSAUtil.saveFile(DES_ENCRYPT_TEMP_FILE,cipherText);
			
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
			KeyFactory keyFactoryPrv = KeyFactory.getInstance(RSAUtil.ALGORITHM);
			PrivateKey prkey = keyFactoryPrv.generatePrivate(specPrv);
			final String plainText = RSAUtil.decrypt(cipherText, prkey);
			final String plainText2 = RSAUtil.decrypt(
					RSAUtil.getDESValue(DES_ENCRYPT_TEMP_FILE), prkey);
			final String plainText3 = RSAUtil.decrypt(RSAUtil.getDESValue(DES_ENCRYPT_FILE), prkey);

			// Printing the Original, Encrypted and Decrypted Text
			System.out.println("Original(待加密内容): " + originalText);
			System.out.println("Encrypted(): " + cipherText.toString());
			System.out.println("Decrypted(解密后的内容，和待加密内容理应保持一致): " + plainText);
			System.out.println("Decrypted(对生成的des temp文件解密后的内容): " + plainText2);
			System.out.println("Decrypted(对des encrypt文件解密后的内容): " + plainText3);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
