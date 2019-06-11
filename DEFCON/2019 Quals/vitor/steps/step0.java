package ooo.vitor;

import android.content.Context;
import android.net.Uri;
import android.webkit.WebView;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class fc {
    private static final byte[] initVector = new byte[]{(byte) 19, (byte) 55, (byte) 19, (byte) 55, (byte) 19, (byte) 55, (byte) 19, (byte) 55, (byte) 19, (byte) 55, (byte) 19, (byte) 55, (byte) 19, (byte) 55, (byte) 19, (byte) 55};
    public static boolean mValid = false;
    public static String p1EncFn = "ckxalskuaewlkszdva";
    public static String p1Fn = "nsavlkureaasdqwecz";
    public static String p5EncFn = "cxnvhaekljlkjxxqkq";
    public static String rand2EncFn = "fwswzofqwkzhsgdxfr";
    public static String randEncFn = "zslzrfomygfttivyac";

    public static boolean cf(MainActivity mainActivity, String str) {
        try {
            cfa(mainActivity, p1EncFn);
            cfa(mainActivity, p5EncFn);
            cfa(mainActivity, randEncFn);
            cfa(mainActivity, rand2EncFn);
            if (str.startsWith("OOO{") && str.endsWith("}")) {
                if (str.length() == 45) {
                    if (!cf(mainActivity, dp1(mainActivity, new File(mainActivity.getFilesDir(), p1EncFn), g0(str.substring(4, 44))), str)) {
                        return false;
                    }
                    File file = new File(mainActivity.getFilesDir(), "bam.html");
                    WebView webView = mainActivity.mWebView;
                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append("file:///");
                    stringBuilder.append(file.getAbsolutePath());
                    stringBuilder.append("?flag=");
                    stringBuilder.append(Uri.encode(str));
                    webView.loadUrl(stringBuilder.toString());
                    return mValid;
                }
            }
        } catch (Exception unused) {
        }
        return false;
    }

    public static byte[] g0(String str) {
        int i;
        byte[] bArr = new byte[4];
        byte[] bytes = str.getBytes();
        for (i = 0; i < 4; i++) {
            bArr[i] = (byte) 0;
        }
        for (i = 0; i < 10; i++) {
            for (int i2 = 0; i2 < 4; i2++) {
                bArr[i2] = (byte) (bArr[i2] ^ bytes[(i * 4) + i2]);
            }
        }
        return bArr;
    }

    private static File cfa(Context context, String str) throws Exception {
        InputStream open = context.getAssets().open(str);
        File file = new File(context.getFilesDir().getAbsolutePath(), str);
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        byte[] bArr = new byte[1024];
        while (true) {
            int read = open.read(bArr);
            if (read != -1) {
                fileOutputStream.write(bArr, 0, read);
            } else {
                open.close();
                fileOutputStream.close();
                return file;
            }
        }
    }

    private static void copyFile(File file, File file2) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(file);
        FileOutputStream fileOutputStream = new FileOutputStream(file2);
        byte[] bArr = new byte[1024];
        while (true) {
            int read = fileInputStream.read(bArr);
            if (read != -1) {
                fileOutputStream.write(bArr, 0, read);
            } else {
                fileInputStream.close();
                fileOutputStream.close();
                return;
            }
        }
    }

    public static byte[] hash(byte[] bArr) throws Exception {
        MessageDigest instance = MessageDigest.getInstance("MD5");
        instance.update(bArr);
        return instance.digest();
    }

    private static File dp1(Context context, File file, byte[] bArr) throws Exception {
        bArr = hash(bArr);
        byte[] readAllBytes = Files.readAllBytes(file.toPath());
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
            SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
            Cipher instance = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            instance.init(2, secretKeySpec, ivParameterSpec);
            readAllBytes = instance.doFinal(readAllBytes);
            File file2 = new File(context.getFilesDir(), p1Fn);
            FileOutputStream fileOutputStream = new FileOutputStream(file2);
            fileOutputStream.write(readAllBytes, 0, readAllBytes.length);
            fileOutputStream.flush();
            fileOutputStream.close();
            return file2;
        } catch (Exception unused) {
            return null;
        }
    }

    private static boolean cf(Context context, File file, String str) {
        File file2 = new File(context.getFilesDir().getAbsolutePath());
        DexClassLoader dexClassLoader = new DexClassLoader(file.getAbsolutePath(), file2.getAbsolutePath(), file2.getAbsolutePath(), ClassLoader.getSystemClassLoader());
        boolean z = false;
        try {
            Class loadClass = dexClassLoader.loadClass("ooo.p1.P1");
            z = ((Boolean) loadClass.getDeclaredMethod("cf", new Class[]{Context.class, String.class}).invoke(loadClass, new Object[]{context, str})).booleanValue();
            return z;
        } catch (Exception unused) {
            return z;
        }
    }
}
