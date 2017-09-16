package core.hdcon.android_2017;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class aes256 {
    public static void encrypt(byte[] i, ByteArrayOutputStream o, String k) {
        ee(1, i, o, k);
    }

    public static void decrypt(byte[] i, ByteArrayOutputStream o, String k) {
        ee(2, i, o, k);
    }

    private static void ee(int m, byte[] i, ByteArrayOutputStream o, String kk) {
        try {
            byte[] k = kk.getBytes();
            byte[] iv = new byte[]{(byte) 9, (byte) 8, (byte) 7, (byte) 6, (byte) 5, (byte) 4, (byte) 3, (byte) 2, (byte) 1, (byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6};
            SecretKey aesKey = new SecretKeySpec(k, 0, k.length, "AES");
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(m, aesKey, new IvParameterSpec(iv));
            o.write(c.doFinal(i));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (InvalidKeyException e3) {
            e3.printStackTrace();
        } catch (IllegalBlockSizeException e4) {
            e4.printStackTrace();
        } catch (BadPaddingException e5) {
            e5.printStackTrace();
        } catch (IOException e6) {
            e6.printStackTrace();
        } catch (InvalidAlgorithmParameterException e7) {
            e7.printStackTrace();
        }
    }
}
