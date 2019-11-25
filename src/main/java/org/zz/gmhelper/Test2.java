package org.zz.gmhelper;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.zz.gmhelper.cert.SM2CertUtil;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.RandomAccessFile;
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

    public static void main(String[] args) throws CertificateException, NoSuchProviderException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, CryptoException {
        X509Certificate cert = SM2CertUtil.getX509Certificate("target/ServerCA.crt");
        BCECPublicKey pubKey = SM2CertUtil.getBCECPublicKey(cert);
        byte[] keyBytes = parseDERFromPEM(Test2.readFile("target/ServerPkcs8.pem"), "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        BCECPrivateKey privateKey = Test2.generatePrivateKeyFromDER(keyBytes);
        System.out.println(privateKey.getAlgorithm());

        byte[] sign = SM2Util.sign(privateKey,Test2.SRC_DATA_32B);
        Boolean flage = SM2Util.verify(pubKey,Test2.SRC_DATA_32B,sign);
        System.out.println(flage);

        String content ="hello world";
        byte[] result = SM2Util.decrypt(privateKey,SM2Util.encrypt(pubKey,content.getBytes()));
        System.out.println(new String(result));

    }

}
