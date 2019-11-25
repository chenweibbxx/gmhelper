package com.whhx.input.util.crypto;

import java.io.*;

/**
 * 序列化和反序列化工具
 * */
public class SerializationUtils {

    private static String FILE_NAME = "C:\\Users\\Administrator\\Desktop\\envelopedDataObj";

    //序列化
    public static void write(Serializable s){
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(FILE_NAME));
            objectOutputStream.writeObject(s);
            objectOutputStream.close();
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    //反序列化
    public static Object read(){
        Object obj = null;
        try {
            ObjectInput objectInput = new ObjectInputStream(new FileInputStream(FILE_NAME));
            obj = objectInput.readObject();
            objectInput.close();
        }catch (Exception e){
            e.printStackTrace();
        }
        return obj;
    }
}
