package com.kim.test;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Test;

import com.kim.util.EncryptUtil;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
/**
 * 
 * @author Kim
 * 
 * 各种加密算法：
 * 		1、不可逆算法：MD5\SHA1
 * 		2、可逆算法：BASE64\HEX
 *		3、安全加密方法：encryptCode = HEX.ENCODE(RANDOM) + HEX.ENCODE(SHA1(RANDOM+password))
 */
public class EncryptTest {
	
	//不可逆加密算法     MD5
	@Test
	public void MD5Test(){
		String password = "123456";
		System.out.println(DigestUtils.md5Hex(password.getBytes()));
		//e10adc3949ba59abbe56e057f20f883e
	}
	
	//不可逆加密算法     SHA1
	@Test
	public void SHA1Test(){
		String password = "123456";
		System.out.println(DigestUtils.sha1Hex(password.getBytes()));
		//7c4a8d09ca3762af61e59520943dc26494f8941b
	}
	
	//测试可逆加密算法BASE64
	@Test
	public void testBASE64Encode(){
		String password = "123456";
		System.out.println(Base64.encode(password.getBytes()));
		//MTIzNDU2
	}
		
	//测试可逆加密算法BASE64
	@Test
	public void testBASE64Decode() throws Base64DecodingException{
		String encryptPsd = "MTIzNDU2";
		System.out.println(new String(Base64.decode(encryptPsd.getBytes())));
		//123456
	}
	
	//测试可逆加密算法HEX
	@Test
	public void testHEXEncode(){
		String password = "123456";
		System.out.println(Hex.encodeHex(password.getBytes()));
		//313233343536
	}
		
	//测试可逆加密算法HEX
	@Test
	public void testHexDecode() throws DecoderException{
		String encryptPsd = "313233343536";
		System.out.println(new String(Hex.decodeHex(encryptPsd.toCharArray())));		
		//123456
	}
	
	
	/**
	  * 1:生成一个随机数 
	  * 2:用可逆的加密算法加密随机数
	  * 3:将随机数和我们的密码 用sha1不可逆算法加密
	  * 4:将第三步得到的字符串值用可逆的加密算法加密
	  * 5:将第2步和第4步的值拼凑
	  * 加密： encryptCode = HEX.ENCODE(RANDOM) + HEX.ENCODE(SHA1(RANDOM+password))
	  */
	
	@Test
	public void testPmEncrypt(){
		EncryptUtil encryptUtil = new EncryptUtil();
		
		String plainPsd = "123456";
		//1
		byte[] random = encryptUtil.generateSalt(8);
		//2
		String randomHex = encryptUtil.encodeHex(random);
		//3+4
		String sha1Psd = encryptUtil.encodeHex(encryptUtil.sha1(plainPsd.getBytes(), random, 1024)); 
		//5
		String encryptPsd = randomHex + sha1Psd;
		
		System.out.println("加密盐值：" + random);
		System.out.println("密文：" + encryptPsd);
		
		//带盐加密：密码相同加密后密文也不一样
		
		//801a17dd213aadaa8c5e4cd27bad56e9769b70bc6e70b41d796cbfb1
		//bfcbcaad25967e4c62ebc7535e6851b10997dba471dc8ab562fbdb80

	}
	
	
	//密码验证
 	@Test
 	public void testPsdValidator(){
 		String password = "123456";
 		String encryptPsd = "0bb33a64e4651c4518de2efdac05f621fb31e1035f52e1ac26576e65";
 		//将密文逆转 ，截取 salt盐的明文
 		byte[] salt = EncryptUtil.decodeHex(encryptPsd.substring(0, 16));
 		 		
 		//重新拼凑 盐+密码   进行sha1的加密
 	    byte[] hashPass = EncryptUtil.sha1(password.getBytes(), salt, 1024);
 	    String newEcnryptPsd= EncryptUtil.encodeHex(salt) + EncryptUtil.encodeHex(hashPass);
 	    System.out.println("加密盐值：" + salt);
		System.out.println("新密文：" + newEcnryptPsd);
 	}
	
}
