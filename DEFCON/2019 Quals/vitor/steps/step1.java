package ooo.p1;

import android.content.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class P1 {
    public static String abc = "smnvlwkuelqkjsmxzz";
    public static String def = "mmdffuoscjdamcnssn";
    public static String ghi = "xtszswemcwohpluqmi";

    /* renamed from: ooo reason: collision with root package name */
    private static final byte[] f0ooo = {19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55, 19, 55};

    private native String xxx(String str, String str2);

    public static boolean cf(Context ctx, String f) {
        try {
            byte[] K1 = g1(f.substring(4, 44));
            cfa(ctx, def);
            cfa(ctx, ghi);
            dp2(ctx, new File(ctx.getFilesDir(), def), K1);
            System.loadLibrary(abc);
            String tre = new P1().xxx(f, ctx.getFilesDir().getAbsolutePath());
            if (tre != null && new File(tre).isFile()) {
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] g1(String f) {
        byte[] K1 = new byte[4];
        byte[] fb = f.getBytes();
        for (int j = 0; j < 4; j++) {
            K1[j] = 0;
        }
        for (int i = 0; i < 10; i += 2) {
            for (int j2 = 0; j2 < 4; j2++) {
                K1[j2] = (byte) (K1[j2] ^ fb[((i + 1) * 4) + j2]);
            }
        }
        return K1;
    }

    private static void cff(File src, File dst) throws Exception {
        InputStream in = new FileInputStream(src);
        OutputStream out = new FileOutputStream(dst);
        byte[] buffer = new byte[1024];
        while (true) {
            int read = in.read(buffer);
            int read2 = read;
            if (read != -1) {
                out.write(buffer, 0, read2);
            } else {
                in.close();
                out.close();
                return;
            }
        }
    }

    public static byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(in);
        return md.digest();
    }

    private static File dp2(Context ctx, File p2Enc, byte[] K1) throws Exception {
        byte[] enckey = hash(K1);
        byte[] ct = Files.readAllBytes(p2Enc.toPath());
        try {
            IvParameterSpec iv = new IvParameterSpec(f0ooo);
            SecretKeySpec skeySpec = new SecretKeySpec(enckey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(2, skeySpec, iv);
            byte[] pt = cipher.doFinal(ct);
            File filesDir = ctx.getFilesDir();
            StringBuilder sb = new StringBuilder();
            sb.append("lib");
            sb.append(abc);
            sb.append(".so");
            File p2file = new File(filesDir, sb.toString());
            OutputStream out = new FileOutputStream(p2file);
            out.write(pt, 0, pt.length);
            out.flush();
            out.close();
            return p2file;
        } catch (Exception e) {
            return null;
        }
    }

    private static File cfa(Context ctx, String fileName) throws Exception {
        InputStream in = ctx.getAssets().open(fileName);
        File outFile = new File(ctx.getFilesDir().getAbsolutePath(), fileName);
        OutputStream out = new FileOutputStream(outFile);
        byte[] buffer = new byte[1024];
        while (true) {
            int read = in.read(buffer);
            int read2 = read;
            if (read != -1) {
                out.write(buffer, 0, read2);
            } else {
                in.close();
                out.close();
                return outFile;
            }
        }
    }
}
