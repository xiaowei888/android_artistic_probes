package com.android.server.pm;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import android.content.Context;
import org.apache.commons.codec.binary.Base64;
import android.util.Log;
import android.os.SystemProperties;


public class ReadHeadInfo {
	
	
	//==============================分割线==========================================
	
	public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	public static final String ENCODE_ALGORITHM = "SHA-256";
	static String publicRootKeyPath = "/system/PubKey_ROOT_20151205.pem";
	static String file_name = "46494c455f5349474e5f4d41524b";
	
	/**
	 * 签名后的apk解析成byte
	 */
	private static  byte[] orignalApkArray;
	/**
	 * 签名前的apk源文件
	 */
	private static  byte[] oriApk;
	/**
	 * 签名信息
	 */
	private static  byte[] signInfo;
	/**
	 * 文件头标识字符串
	 */
	private static  String signHeadFlag;
	/**
	 * 通联签名扩展标识字符串
	 */
	private static  String allinpaySignFlag;
	
	/**
	 * 工作证书
	 */
	private static  byte[] pubCertificateByteArray;


	/**
	 * 校验magic
	 * 
	 * @param magic
	 * @return
	 */
	public static  boolean verifyMagic() {
		//保留接口不实现
		return true;
	}

	/**
	 * 校验version
	 * 
	 * @param version
	 * @return
	 */
	public static  boolean verifyVersion() {
		//保留接口不实现
		return true;
	}

 
	public static  boolean isVerifyAPK() {
		//verify APK?
		if (SystemProperties.get("persist.sys.changemode").equals("1")) {
                   return false;
                }

		if (SystemProperties.get("persist.sys.changemode").equals("0")) {
                   return true;
                }
                
		/*if (SystemProperties.get("persist.sys.sd.defaultpath").equals("/storage/emulated/0")) {
                   return false;
                }

		if (SystemProperties.get("persist.sys.sd.defaultpath").equals("/storage/sdcard0")) {
                   return true;
                }*/

		return false;		
	}

	
	/**
	 * 解析签名后的apk
	 * 
	 * @param1 签名后的文件路径
	 * @param2 签名前的文件重新保存路径
	 * @return
	 */
	public static  boolean analyzeApk(String apkPath, String newapkPath) {

		boolean result = false;
		Process p = null;
		int status = 0;
		
		/**
		 * 签名后的apk源文件
		 */
		orignalApkArray = null;
		/**
		 * 签名前的apk源文件
		 */
		oriApk = null;
		/**
		 * 签名信息
		 */
		signInfo = null;
		
		pubCertificateByteArray = null;
		/**
		 * 文件头标识字符串
		 */
		signHeadFlag = "";
		/**
		 * 通联签名扩展标识字符串
		 */
		allinpaySignFlag = "";

//		File file = new File(apkPath);
//		String filePath = file.getAbsolutePath();
//		String[] dataStr = filePath.split("/");
//		String fileTruePath = "/data/media/0";
//
//		if(apkPath.contains("/storage/emulated/0")) {
//		for(int i=4;i<dataStr.length;i++){
//
//			fileTruePath = fileTruePath+"/"+dataStr[i];
//		}
//	    Log.e("XBY", "apkPath 1: "+apkPath);
//		apkPath = fileTruePath;
//	    Log.e("XBY", "apkPath 2: "+apkPath);
//		}
//
//		if(apkPath.contains("/storage/sdcard0")) {
//		for(int i=3;i<dataStr.length;i++){
//
//			fileTruePath = fileTruePath+"/"+dataStr[i];
//		}
//	    Log.e("XBY", "apkPath 1: "+apkPath);
//		apkPath = fileTruePath;
//	    Log.e("XBY", "apkPath 2: "+apkPath);
//		}
//
//		try {
//
//			//p = Runtime.getRuntime().exec("chmod 777 " +  "data/media" );
//			//p = Runtime.getRuntime().exec("chmod 777 " +  "data/media/0" );
//			p = Runtime.getRuntime().exec("chmod 777 " +  apkPath );
//		} catch (IOException e) {
//
//			e.printStackTrace();
//		}
//		try {
//
//			status = p.waitFor();
//		} catch (InterruptedException e) {
//
//			e.printStackTrace();
//		}   
//		if (status == 0) {
//			    
//		} else {
//			    
//		}

		File orignalApk = new File(apkPath);
	    Log.e("XBY", "new File: "+orignalApk);
		try {
			orignalApkArray = readFileBytes(orignalApk);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if(orignalApkArray.length<=0)
			return false;
		
		File orignalApkFile = new File(apkPath);
		try {
			orignalApkArray = readFileBytes(orignalApkFile);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		byte[] sign_extends_offset;
		byte[] sign_data;
		byte[] certificate_length;
		byte[] oriApk_length;
		byte[] filename;

        filename= new byte[14];
		System.arraycopy(orignalApkArray, orignalApkArray.length - 60, filename, 0, 14);
		String fileheader = bytesToHexString(filename);
		System.out.println("bytesToHexString="+fileheader);
		if(fileheader.equals(file_name)== false)
	    {
           System.out.println("string are not same");
		   return false;
		}	

		System.out.println("string are same");

        oriApk_length = new byte[4];
		System.arraycopy(orignalApkArray, orignalApkArray.length - 38, oriApk_length, 0, 4);
		certificate_length = new byte[4];
		System.arraycopy(orignalApkArray, orignalApkArray.length - 4, certificate_length, 0, 4);
		sign_extends_offset = new byte[4];
		System.arraycopy(orignalApkArray, orignalApkArray.length - 10, sign_extends_offset, 0, 4);

		int oriApk_size = bytesToint(oriApk_length);  //yuanwenjiandaxiao
		System.out.println("yuanwenjiandaxiao= "+oriApk_size);
		int offset = bytesToint(sign_extends_offset);  //qian ming shu ju pian yi
		System.out.println("qian ming data pianyi= "+offset);
		int size = bytesToint(certificate_length);  //qian ming xinxi da xiao
		System.out.println("qian ming data size= "+size);

		sign_data = new byte[orignalApkArray.length-offset];
		System.arraycopy(orignalApkArray, offset, sign_data, 0, size);		
		signInfo = new byte[256];
		System.arraycopy(sign_data, 0, signInfo, 0, 256);
		
		System.out.println("signInfo= "+bytesToHexString(signInfo));
		certificate_length = new byte[4];
		System.arraycopy(sign_data, 256, certificate_length, 0, 4);
		System.out.println("certificate_length="+bytesToint(certificate_length));
		pubCertificateByteArray = new byte[bytesToint(certificate_length)];
		System.arraycopy(sign_data, 256 + 4, pubCertificateByteArray, 0, bytesToint(certificate_length));
		
		System.out.println("pubCertificateByteArray="+bytesToHexString(certificate_length));
		
		oriApk = new byte[bytesToint(sign_extends_offset)];
		System.arraycopy(orignalApkArray, 0, oriApk, 0,bytesToint(sign_extends_offset));	
		
		if (veriFication(publicRootKeyPath)) {
			result = true;
			writeFile(oriApk, newapkPath );
		}
		
			
		p = null;
		status = 0;

		try {

			p = Runtime.getRuntime().exec("chmod 777 " +  newapkPath );
		} catch (IOException e) {

			e.printStackTrace();
		}
		try {

			status = p.waitFor();
		} catch (InterruptedException e) {

			e.printStackTrace();
		}   
		if (status == 0) {
			    
		} else {
			    
		}
		
		return result;

	}
	
	/**
	 * 小端字节数据转换整数
	 * @return
	 */
	public static int bytesToint(byte[] data) {
		return data[0] & 0xFF | (data[1] & 0xFF) << 8 | (data[2] & 0xFF) << 16
				| (data[3] & 0xFF) << 24;
	}


	/**
	 * 将字节数组写入文件
	 * 
	 * @param apkfile
	 * @param path
	 */
	
	public static  boolean writeFile(byte[] data, String path) {

       FileOutputStream out = null;
//	    File destDir = new File("/data/local/share");
//      if (!destDir.exists()) {
//          destDir.mkdirs();
//      }
//		Process p = null;
//		int status = 0;
//
//		try {
//
//	        Log.e("XBY", "mkdir /data/local/share");
//			p = Runtime.getRuntime().exec("chmod 777 " +  "/data/local/share" );
//		} catch (IOException e) {
//
//			e.printStackTrace();
//		}
//		try {
//
//			status = p.waitFor();
//		} catch (InterruptedException e) {
//
//			e.printStackTrace();
//		}   
//		if (status == 0) {
//			    
//		} else {
//			    
//		}
	       try {
	               out = new FileOutputStream(path); 
	               out.write(data);
	               out.close();
	               return true; 
	               
	       } catch (Exception e) {
	               Log.e("XBY", "Failed to write data", e);
	               e.printStackTrace();
	   			   return false;
	       }                                                                                                          
	}
	

	/**
	 * byte 转Ascii
	 * 
	 * @param bytes
	 * @param offset
	 * @param dateLen
	 * @return
	 */

	public static  String bytesToAscii(byte[] bytes, int offset, int dateLen) {
		if ((bytes == null) || (bytes.length == 0) || (offset < 0) || (dateLen <= 0)) {
			return null;
		}
		if ((offset >= bytes.length) || (bytes.length - offset < dateLen)) {
			return null;
		}

		String asciiStr = null;
		byte[] data = new byte[dateLen];
		System.arraycopy(bytes, offset, data, 0, dateLen);
		try {
			asciiStr = new String(data, "utf-8");
		} catch (Exception e) {
		}
		return asciiStr;
	}

	/**
	 * 以二进制读取文件
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	public static byte[] readFileBytes(File file) throws IOException {

		Log.e("XBY", "readFileBytes: 11");
		FileInputStream stream = new FileInputStream(file);
		Log.e("XBY", "readFileBytes: 22");

		int length = (int) file.length();
		byte[] data = new byte[length];
		try {

			int offset = 0;
			while (offset < length) {

				offset += stream.read(data, offset, length - offset);
			}
		} catch (IOException e) {

			throw e;
		} finally {

			stream.close();
		}
		return data;
	}

	
	/**
	 * bytes[]换成16进制字符串
	 * 
	 * @param src
	 * @return
	 */
	public static String bytesToHexString(byte[] src) {
		StringBuilder stringBuilder = new StringBuilder("");
		if (src == null || src.length <= 0) {
			return null;
		}
		for (int i = 0; i < src.length; i++) {
			int v = src[i] & 0xFF;
			String hv = Integer.toHexString(v);
			if (hv.length() < 2) {
				stringBuilder.append(0);
			}
			stringBuilder.append(hv);
		}
		return stringBuilder.toString();
	}
	
	
	/**
	 * 根证书验证工作证书
	 * 
	 * @param1 RootCertificate
	 * @param2 WorkCertificate
	 * @return 
	 */
	public static  boolean Verify_WorkCertificate(X509Certificate RootCertificate, X509Certificate WorkCertificate) {
		
		try {
			WorkCertificate.verify(RootCertificate.getPublicKey());
			return true;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * 从证书文件中加载证书
	 * 
	 * @param certificateFilePath
	 * @return 
	 */
	private static X509Certificate loadX509CertificateformFILE(String certificateFilePath) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(certificateFilePath));
            return x509Certificate;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	/**
	 * 从证书数组中加载证书
	 * 
	 * @param certificateByteArray
	 * @return 
	 */
	private static X509Certificate loadX509CertificateformByteArray(byte[] certificateByteArray) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateByteArray));
            return x509Certificate;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
	/**
	 * 通联apk验签函数，供PMS调用
	 * 
	 * @param 根证书文件路径
	 * @return 
	 */
	public static  boolean veriFication(String rootCertificateFilePath) {
		
		boolean result = false;
		boolean result1 = false;
		boolean result2 = false;
		
		X509Certificate rootCertificate = loadX509CertificateformFILE(rootCertificateFilePath);
		X509Certificate workCertificate = loadX509CertificateformByteArray(pubCertificateByteArray);
		
		if(rootCertificate==null||workCertificate==null)
			return false;
		
		result= Verify_WorkCertificate(rootCertificate, workCertificate);
		
		byte[] decodeInfo = asymmetricDecrypt(signInfo,workCertificate.getPublicKey());
		
		try {
			
			MessageDigest messageDigest;
			messageDigest = MessageDigest.getInstance(ENCODE_ALGORITHM);
			messageDigest.update(oriApk);
			byte[] oriApkDigest = messageDigest.digest();
			
			String strDecodeInfo = bytesToHexString(decodeInfo);
			String strOriApkDigest = bytesToHexString(oriApkDigest);
			
			//System.out.println("原始应用SHA256数字摘: " + strOriApkDigest);
			//System.out.println("SHA256withRSA解密后: " + strDecodeInfo);
						
			if(strDecodeInfo.endsWith(strOriApkDigest))
				result1 = true;
			
			Signature verifySign = Signature.getInstance(SIGNATURE_ALGORITHM);
			verifySign.initVerify(workCertificate.getPublicKey());
			verifySign.update(oriApkDigest);
			result2 = verifySign.verify(signInfo);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		
		Log.e("XBY","veriFication：result=" + result + "; result1=" + result1 + "; result2=" + result2);
		
		return (result&&result1);
	}
	
	/**
	 * 解密加签后的数据，得到pkcs#1填充后的摘要数据
	 * 
	 * @param1 签名后的数据
	 * @param2 验证公钥
	 * @return 
	 */
	public static byte[] asymmetricDecrypt(byte[] signInfo1, PublicKey publicKey){  
	      
        try {
        	Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			cipher.update(signInfo1);
			return cipher.doFinal();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }
}
