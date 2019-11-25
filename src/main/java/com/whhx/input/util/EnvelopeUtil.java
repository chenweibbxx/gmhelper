package com.whhx.input.util;

import com.whhx.input.util.crypto.*;
import com.whhx.input.util.envelope.*;
import org.bouncycastle.math.ec.ECPoint;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EnvelopeUtil {

    public static String version = "ASN.1";

    //加密
    public static void encrypt() {
        try {

            //待加密内容
            String content = "hello world";

            //生成对称密钥
            byte[] secretKey = SM4Utils.generateKey();

            //生成非对称密钥(公钥、私钥)
            String path = "C:\\Users\\Administrator\\Desktop\\";
            SM2KeyPair keyPair = SM2Utils.generateKeys(path);
            //导入公钥（获取公钥）
            //ECPoint publickey = SM2Utils.importPubkey(path);

            /*//使用公钥 加密 密钥
            byte[] result = SM2Utils.encrypt("MSG",publickey);

            //导入私钥(获取私钥)
            BigInteger privateKey =  SM2Utils.importPrikey(path);
            String msg = SM2Utils.decrypt(result,privateKey);*/

            //对称加密-加密信息
            String encryContent = SM4Utils.encryptData_ECB(content, secretKey);
            System.out.println(encryContent);

            //数字信封
            EnvelopedData envelopedData = new EnvelopedData();

            //接收者信息
            List<RecipientInfo> recipientInfos = new ArrayList<>();
            RecipientInfo recipientInfo = new RecipientInfo();
            //版本号
            recipientInfo.setVersion(version);
            //发送者标识
            recipientInfo.setIssuerAndSerialNumber("JW");
            //加密方法
            recipientInfo.setKeyEncryptionAlgorithm("SM4");
            //加密后的对称密钥(secretKey)
            String temp = new String(secretKey);
            byte[] encryptedkey = SM2Utils.encrypt(temp, keyPair.getPublicKey());
            recipientInfo.setEncryptedKey(encryptedkey);
            //把接收者添加入接受者集合(可以有多个接收者)
            recipientInfos.add(recipientInfo);
            envelopedData.setRecipientInfos(recipientInfos);

            //加密内容结构
            EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo();
            //待加密内容类型
            encryptedContentInfo.setContentype("String");
            //加密方式
            encryptedContentInfo.setContentencryptionalgorithmldentifier("SM4");
            //加密后的内容
            encryptedContentInfo.setEncryptedcontent(encryContent);
            envelopedData.setEncryptedContentInfo(encryptedContentInfo);

            //签名内容
            Signeddata signeddata = new Signeddata();
            //版本号
            signeddata.setVersion(version);
            //摘要算法集合(使用sm3计算摘要)
            List<String> digest = Arrays.asList("SM3");
            signeddata.setDigestAlgorithms(digest);
            //加密内容摘要
            signeddata.setContentInfo(SM3Utils.encrypt(content));
            //证书集合(目前没有证书，生成证书后放入集合中)
            File[] files = null;
            //signeddata.setCertificates(files);
            //撤销证书集合
            List<String> list = Arrays.asList("");
            //signeddata.setCris(list);

            //签名者信息集合
            List<SignerInfo> signerInfos = new ArrayList<>();
            SignerInfo signerInfo = new SignerInfo();
            signerInfo.setVersion(version);
            //证书序列号(暂时没有)
            signerInfo.setIssuerAndSerialNumber("1001");
            //摘要算法
            signerInfo.setDigestAlgorithms("SM3");
            //sm2数字签名算法标识符(非对称加密)
            signerInfo.setDigestEncryptionAlgorithm("SM2");
            //加密后的签名
            //签名者的唯一标识
            String signIdentify = "jw001";
            //内容摘要
            String contentDigest = SM3Utils.encrypt(content);
            //签名用非对称密钥
            SM2KeyPair keyPair2 = SM2Utils.generateKeys(path);
            //生成数字签名
            Signature signature = SM2Utils.sign(contentDigest, signIdentify, keyPair2);
            signerInfo.setEncryptedDigest(signature);
            signerInfos.add(signerInfo);
            signeddata.setSignerInfos(signerInfos);

            envelopedData.setSigneddata(signeddata);

            envelopedData.setVersion(version);

            //加密后的字符串
//            String envelopedDataStr = JSONObject.toJSONString(envelopedData);
//            System.out.println(envelopedDataStr);
//            加密后的实体类 序列化到文件
            SerializationUtils.write(envelopedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //解密
    public static void decode() {
//        EnvelopedData envelopedData = JSONObject.parseObject(envelopedDataStr, EnvelopedData.class);
        //反序列化获取envelopedData
        EnvelopedData envelopedData = (EnvelopedData)SerializationUtils.read();
        try {
            //取出非对称加密后的对称密钥
            RecipientInfo recipientInfo = envelopedData.getRecipientInfos().get(0);
            byte[] encryptedkey = recipientInfo.getEncryptedKey();
            //导入私钥
            //导入私钥(获取私钥)
            BigInteger privateKey = SM2Utils.importPrikey("C:\\Users\\Administrator\\Desktop\\privatekey_1574415713513.pem");
            //解密后的对称密钥
            String secretKey = SM2Utils.decrypt(encryptedkey, privateKey);

            //对称加密后的内容
            String encryptedContent = envelopedData.getEncryptedContentInfo().getEncryptedcontent();
            //对称解密
            String content = SM4Utils.decryptData_ECB(encryptedContent, secretKey.getBytes());

            //验签
            String digest = SM3Utils.encrypt(content);

            SignerInfo signerInfo = envelopedData.getSigneddata().getSignerInfos().get(0);
            //签名者的唯一标识
            String signIdentify = "jw001";
            //导入公钥（获取公钥）
            ECPoint publickey = SM2Utils.importPubkey("C:\\Users\\Administrator\\Desktop\\publickey_1574415713544.pem");
            boolean flag = SM2Utils.verifySign(digest,signerInfo.getEncryptedDigest(),signIdentify,publickey);
            if (flag) {
                System.out.println("内容可用");
                System.out.println("解密后的内容content :" + content);
            } else {
                throw new Exception("验签未通过");
            }




        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
//        encrypt();
        decode();
    }
}
