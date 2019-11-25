package com.whhx.input.util.envelope;

import java.io.Serializable;

public class RecipientInfo implements Serializable {

    private String Version;
    private String issuerAndSerialNumber;        //颁发者可辨别名和办法序列号
    private String keyEncryptionAlgorithm;       //sm2加密算法 用来加密 数据加密秘钥
    private byte[] encryptedKey;                 //数据加密秘钥密文sm2cipher

    public String getVersion() {
        return Version;
    }

    public void setVersion(String version) {
        Version = version;
    }

    public String getIssuerAndSerialNumber() {
        return issuerAndSerialNumber;
    }

    public void setIssuerAndSerialNumber(String issuerAndSerialNumber) {
        this.issuerAndSerialNumber = issuerAndSerialNumber;
    }

    public String getKeyEncryptionAlgorithm() {
        return keyEncryptionAlgorithm;
    }

    public void setKeyEncryptionAlgorithm(String keyEncryptionAlgorithm) {
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    }

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
    }
}
