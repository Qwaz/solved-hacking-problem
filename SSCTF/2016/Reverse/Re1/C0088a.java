import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/* renamed from: com.ssctf.seclreg.a */
public class C0088a {
    private static int m587a(char c) {
        return c >= 'a' ? ((c - 97) + 10) & 15 : c >= 'A' ? ((c - 65) + 10) & 15 : (c - 48) & 15;
    }

    public static String m588a(String str, String str2) {
        try {
            Key b = C0088a.m590b(str2);
            Cipher instance = Cipher.getInstance("DES/ECB/NoPadding");
            instance.init(1, b, new SecureRandom());
            return new String(instance.doFinal(str.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] m589a(String str) {
        int i = 0;
        byte[] bArr = new byte[(str.length() / 2)];
        int i2 = 0;
        while (i < bArr.length) {
            int i3 = i2 + 1;
            char charAt = str.charAt(i2);
            i2 = i3 + 1;
            int a = C0088a.m587a(charAt) << 4;
            bArr[i] = (byte) (C0088a.m587a(str.charAt(i3)) | a);
            i++;
        }
        return bArr;
    }

    private static SecretKey m590b(String str) {
        try {
            return SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(C0088a.m589a(str)));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String []args) {
        String result = C0088a.m588a("secl-007", "A7B7C7D7E7F70717");
        System.out.println(String.format("%x", new BigInteger(1, result.getBytes())));
    }
}
