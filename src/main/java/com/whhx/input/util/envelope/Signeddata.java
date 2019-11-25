package com.whhx.input.util.envelope;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Signeddata implements Serializable {

    private String version;
    private List<String> digestAlgorithms = new ArrayList<>();   //消息摘要算法标识集合
    private String contentInfo;              //被签名的数据内容
    private File[] certificates;             //pkcs6扩展证书和x.509证书集合
    private List<String> cris = new ArrayList<>();                     //证书撤销列表的集合
    private List<SignerInfo> signerInfos = new ArrayList<>();    //签名者信息集合

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<String> getDigestAlgorithms() {
        return digestAlgorithms;
    }

    public void setDigestAlgorithms(List<String> digestAlgorithms) {
        this.digestAlgorithms = digestAlgorithms;
    }

    public String getContentInfo() {
        return contentInfo;
    }

    public void setContentInfo(String contentInfo) {
        this.contentInfo = contentInfo;
    }

    public File[] getCertificates() {
        return certificates;
    }

    public void setCertificates(File[] certificates) {
        this.certificates = certificates;
    }

    public List<String> getCris() {
        return cris;
    }

    public void setCris(List<String> cris) {
        this.cris = cris;
    }

    public List<SignerInfo> getSignerInfos() {
        return signerInfos;
    }

    public void setSignerInfos(List<SignerInfo> signerInfos) {
        this.signerInfos = signerInfos;
    }
}
