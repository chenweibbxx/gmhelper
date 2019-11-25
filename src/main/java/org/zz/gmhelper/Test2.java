package org.zz.gmhelper;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.zz.gmhelper.cert.SM2CertUtil;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

//测试证书和私钥
public class Test2 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final byte[] SRC_DATA = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    public static final byte[] SRC_DATA_16B = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    public static final byte[] SRC_DATA_24B = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    public static final byte[] SRC_DATA_32B = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    public static final byte[] WITH_ID = new byte[]{1, 2, 3, 4};


    protected static byte[] readFile(String filePath) throws IOException {
        byte[] data;
        try (RandomAccessFile raf = new RandomAccessFile(filePath, "r")) {
            data = new byte[(int) raf.length()];
            raf.read(data);
            return data;
        }
    }

    protected static byte[] parseDERFromPEM(byte[] pem, String beginDelimiter, String endDelimiter) {
        String data = new String(pem);
        String[] tokens = data.split(beginDelimiter);
        tokens = tokens[1].split(endDelimiter);
        return DatatypeConverter.parseBase64Binary(tokens[0]);
    }

    protected static BCECPrivateKey generatePrivateKeyFromDER(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return (BCECPrivateKey) kf.generatePrivate(peks);
    }


    private static final String TEST_CA_FILENAME = "E:\\IdeaProjects\\gmhelper\\src\\main\\resources\\ServerCA.crt";
    private static final String TEST_PRI_KEY_FILENAME = "E:\\IdeaProjects\\gmhelper\\src\\main\\resources\\ServerPkcs8.pem";

    public static void main(String[] args) throws CertificateException, NoSuchProviderException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, CryptoException {
        //获取证书的公钥
        X509Certificate cert = SM2CertUtil.getX509Certificate(Files.newInputStream(Paths.get(TEST_CA_FILENAME)));
        BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(cert);
        //获取私钥
        byte[] keyBytes = parseDERFromPEM(Test2.readFile(TEST_PRI_KEY_FILENAME), "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        BCECPrivateKey privateKey = Test2.generatePrivateKeyFromDER(keyBytes);
        //确定的EC算法
        System.out.println(privateKey.getAlgorithm());
        String content ="hello world";
        //签名
        byte[] sign = SM2Util.sign(privateKey,content.getBytes());
        //验证签名
        Boolean flag = SM2Util.verify(pubKey,content.getBytes(),sign);
        System.out.println(flag);
        //加密
        byte[] encyContent = SM2Util.encrypt(pubKey,content.getBytes());
        //解密
        byte[] result = SM2Util.decrypt(privateKey,encyContent);
        //打印
        System.out.println(new String(result));

    }

}
