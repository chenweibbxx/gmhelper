package com.whhx.input.util.envelope;

import java.io.Serializable;

public class EncryptedContentInfo implements Serializable {

    private String Contentype;                              //内容的类型
    private String Encryptedcontent;                        //内容加密算法
    private String Sharedinfo;                              //共享信息(可选)
    private String Contentencryptionalgorithmldentifier;    //内容加密算法

    public String getContentype() {
        return Contentype;
    }

    public void setContentype(String contentype) {
        Contentype = contentype;
    }

    public String getEncryptedcontent() {
        return Encryptedcontent;
    }

    public void setEncryptedcontent(String encryptedcontent) {
        Encryptedcontent = encryptedcontent;
    }

    public String getSharedinfo() {
        return Sharedinfo;
    }

    public void setSharedinfo(String sharedinfo) {
        Sharedinfo = sharedinfo;
    }

    public String getContentencryptionalgorithmldentifier() {
        return Contentencryptionalgorithmldentifier;
    }

    public void setContentencryptionalgorithmldentifier(String contentencryptionalgorithmldentifier) {
        Contentencryptionalgorithmldentifier = contentencryptionalgorithmldentifier;
    }
}
