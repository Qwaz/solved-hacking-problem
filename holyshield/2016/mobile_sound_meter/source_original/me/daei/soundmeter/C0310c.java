package me.daei.soundmeter;

import android.os.Environment;
import java.io.File;
import java.io.IOException;

/* renamed from: me.daei.soundmeter.c */
public class C0310c {
    public static final String f1624a;
    public static final String f1625b;

    static {
        f1624a = Environment.getExternalStorageDirectory().getPath() + File.separator;
        f1625b = f1624a + "SoundMeter" + File.separator;
        File file = new File(f1624a);
        if (!file.exists()) {
            file.mkdirs();
        }
        file = new File(f1625b);
        if (!file.exists()) {
            file.mkdirs();
        }
    }

    public static File m2873a(String str) {
        File file = new File(f1625b + str);
        if (file.exists()) {
            file.delete();
        }
        try {
            file.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return file;
    }
}
