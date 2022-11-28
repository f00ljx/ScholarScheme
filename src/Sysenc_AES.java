import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sysenc_AES {
    /**
     * 密钥, 256位32个字节
     */
    public static String DEFAULT_SECRET_KEY = "uBdUx82vPHkDKb284d7NkjFoNcKWBuka";

    private static final String AES = "AES";
    /**
     * 初始向量IV, 初始向量IV的长度规定为128位16个字节, 初始向量的来源为随机生成.
     */
    private static final byte[] KEY_VI = "c558Gq0YQK2QUlMc".getBytes();
    /**
     * 加密解密算法/加密模式/填充方式
     */
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    private static java.util.Base64.Encoder base64Encoder = java.util.Base64.getEncoder();
    private static java.util.Base64.Decoder base64Decoder = java.util.Base64.getDecoder();

    static {
        java.security.Security.setProperty("crypto.policy", "unlimited");
    }

//    public Sysenc_AES(Element ck) {
//        try {
//            MessageDigest md = MessageDigest.getInstance("MD5");// 生成一个MD5加密计算摘要
//            md.update(ck.toBytes());// 计算md5函数
//            this.DEFAULT_SECRET_KEY = md.toString();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//    }
        /**
         * AES加密
         */
        public static String encode (String key, String content){
            try {
                javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), AES);
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(KEY_VI));

                // 获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
                byte[] byteEncode = content.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                // 根据密码器的初始化方式加密
                byte[] byteAES = cipher.doFinal(byteEncode);

                // 将加密后的数据转换为字符串
                return base64Encoder.encodeToString(byteAES);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        /**
         * AES解密
         */
        public static String decode (String key, String content){
            try {
                javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key.getBytes(), AES);
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(KEY_VI));

                // 将加密并编码后的内容解码成字节数组
                byte[] byteContent = base64Decoder.decode(content);
                // 解密
                byte[] byteDecode = cipher.doFinal(byteContent);
                return new String(byteDecode, java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        public static void main (String[]args){
            String dbPassword = "123456";
            String encryptDbPwd = Sysenc_AES.encode(DEFAULT_SECRET_KEY, dbPassword);
            System.out.println("encrypt: " + encryptDbPwd);
//        System.out.println("encrypt: " + base64Decoder.decode(encryptDbPwd));

            String decrypt = Sysenc_AES.decode(DEFAULT_SECRET_KEY, encryptDbPwd);
            System.out.println("decrypt:" + decrypt);
        }
    }
