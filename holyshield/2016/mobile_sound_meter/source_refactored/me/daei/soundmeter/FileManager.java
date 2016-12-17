package me.daei.soundmeter;

import android.os.Environment;
import java.io.File;
import java.io.IOException;

/* renamed from: me.daei.soundmeter.c */
public class FileManager {
    public static final String topDirectory;
    public static final String appDirectory;

    static {
        topDirectory = Environment.getExternalStorageDirectory().getPath() + File.separator;
        appDirectory = topDirectory + "SoundMeter" + File.separator;
        File file = new File(topDirectory);
        if (!file.exists()) {
            file.mkdirs();
        }
        file = new File(appDirectory);
        if (!file.exists()) {
            file.mkdirs();
        }
    }

    public static File allocateFile(String str) {
        File file = new File(appDirectory + str);
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
