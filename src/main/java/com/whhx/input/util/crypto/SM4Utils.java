package com.whhx.input.util.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SM4 加密工具类
 * */
public class SM4Utils {
//	public String getSecretKey() {
//		return secretKey;
//	}
//
//	public void setSecretKey(String secretKey) {
//		this.secretKey = secretKey;
//	}

	public boolean isHexString() {
		return hexString;
	}

	public void setHexString(boolean hexString) {
		this.hexString = hexString;
	}

//	private String secretKey = "";

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

	private String iv = "";

	private boolean hexString = false;

	public SM4Utils()
	{
	}


	/**
	 * SM4 ECB 方式加密
	 * @param plainText 待加密数据
	 * @param secretKey 密钥
	 * */
	public static String encryptData_ECB(String plainText,byte[] secretKey)
	{
		try
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			/*byte[] keyBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
			}
			else
			{
				keyBytes = secretKey.getBytes();
			}*/

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, secretKey);
			byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("GBK"));
			String cipherText = new BASE64Encoder().encode(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0)
			{
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * SM4 ECB方式解密
	 * @param cipherText 待加密数据
	 * @param secretKey 密钥
	 * */
	public static String decryptData_ECB(String cipherText,byte[] secretKey)
	{
		try
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			/*byte[] keyBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
			}
			else
			{
				keyBytes = secretKey.getBytes();
			}*/

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, secretKey);
			byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
			return new String(decrypted, "GBK");
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}

	public String encryptData_CBC(String plainText,String secretKey)
	{
		try
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			}
			else
			{
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("GBK"));
			String cipherText = new BASE64Encoder().encode(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0)
			{
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			return cipherText;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}

	public String decryptData_CBC(String cipherText,String secretKey)
	{
		try
		{
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString)
			{
				keyBytes = Util.hexStringToBytes(secretKey);
				ivBytes = Util.hexStringToBytes(iv);
			}
			else
			{
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, new BASE64Decoder().decodeBuffer(cipherText));
			return new String(decrypted, "GBK");
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}

	//自动生成密钥
	public static byte[] generateKey() throws Exception {
		//return generateKey(128);
		return "JeF8U9wHFOMfs2Y8".getBytes();
	}

	public static byte[] generateKey(int keySize) throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance("SM4", BouncyCastleProvider.PROVIDER_NAME);
		kg.init(keySize,new SecureRandom());
		return kg.generateKey().getEncoded();
	}





}
