package com.whhx.input.util.crypto;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * SM2加密工具类
 * */
public class SM2Utils {

    /**
     * 产生公钥-私钥对，并导出到指定路径
     * @param path 路径 如 E:/
     * */
    public static SM2KeyPair generateKeys(String path){
        SM2 sm2 = new SM2();
        SM2KeyPair keyPair = sm2.generateKeyPair();
        ECPoint publicKey=keyPair.getPublicKey();
        BigInteger privateKey=keyPair.getPrivateKey();
        String currentTime = String.valueOf(System.currentTimeMillis());
        sm2.exportPublicKey(publicKey, path + "publickey" + "_" + currentTime + ".pem");
        sm2.exportPrivateKey(privateKey, path + "privatekey" + "_" + currentTime + ".pem");
        System.out.println("公钥-私钥对生成成功！");
        return keyPair;
    }


    /***/

    /**
     * 导入公钥
     * @param path 文件完整路径 如 E:/xxx.pem
     * */
    public static ECPoint importPubkey(String path){
        SM2 sm2 = new SM2();
        ECPoint publicKey = sm2.importPublicKey(path);
        return publicKey;
    }

    /**
     * 导入私钥
     * @param path 文件完整路径 如 E:/xxx.pem
     * */
    public static BigInteger importPrikey(String path){
        SM2 sm2 = new SM2();
        BigInteger privateKey = sm2.importPrivateKey(path);
        return privateKey;
    }

    /**
     * 公钥加密
     * @param msg 需要加密的信息
     * */
    public static byte[] encrypt(String msg,ECPoint publicKey){
        SM2 sm2 = new SM2();
        byte[] data = sm2.encrypt(msg, publicKey);
        System.out.print("密文:");
        SM2.printHexString(data);
        return data;
    }

    /**
     * 私钥解密
     * */
    public static String decrypt(byte[] data,BigInteger privateKey){
        SM2 sm2 = new SM2();
        String msg  = sm2.decrypt(data, privateKey);
        System.out.println("解密后明文:" + msg);
        return msg;
    }

    /**
     * 生成签名
     * */
    public static Signature sign(String msg,String identification,SM2KeyPair keyPair){
        SM2 sm2 = new SM2();
        return sm2.sign(msg,identification,keyPair);
    }

    /**
     * 校验签名
     * */
    public static boolean verifySign(String msg, Signature signature, String identification, ECPoint publicKey){
        SM2 sm2 = new SM2();
        return sm2.verify(msg,signature,identification,publicKey);
    }


    public static void main(String[] args) {
//        SM2 sm2 = new SM2();
//        SM2KeyPair keyPair = sm2.generateKeyPair();
//        //甲方生成签名
//        Signature signature = SM2Utils.sign("test","wt",keyPair);
//        //乙方校验签名
//        boolean f = SM2Utils.verifySign("test1",signature,"wt",keyPair.getPublicKey());
//        System.out.println(f);
    }



}
