package me.daei.soundmeter;

import android.os.Bundle;
import android.support.v7.p014a.C0231u;
import android.util.Log;
import android.widget.Toast;
import java.io.File;
import me.daei.soundmeter.widget.SoundDiscView;

public class SecondActivity extends C0231u {
    float soundAmplitude;
    boolean recording;
    boolean created;
    private Thread thread;
    SoundDiscView soundDiskView;
    AudioManager audioManager;

    public SecondActivity() {
        this.recording = true;
        this.created = true;
        this.soundAmplitude = 10000.0f;
    }

    private void runThread() {
        this.thread = new Thread(new MyThread(this));
        this.thread.start();
    }

    public void startAudioRecording(File file) {
        try {
            this.audioManager.setFile(file);
            if (this.audioManager.initRecorder()) {
                runThread();
            } else {
                Toast.makeText(this, "start Listen Audio", 0).show();
            }
        } catch (Exception e) {
            Toast.makeText(this, "no permission", 0).show();
            e.printStackTrace();
        }
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(2130968602);
        this.audioManager = new AudioManager();
    }

    protected void onDestroy() {
        if (this.thread != null) {
            this.created = false;
            this.thread = null;
        }
        this.audioManager.cancelRecording();
        super.onDestroy();
    }

    protected void onPause() {
        super.onPause();
        this.recording = false;
        this.audioManager.cancelRecording();
        this.thread = null;
    }

    protected void onResume() {
        super.onResume();
        this.soundDiskView = (SoundDiscView) findViewById(2131492948);
        this.recording = true;
        File file = FileManager.allocateFile("temp.amr");
        if (file != null) {
            Log.v("file", "file =" + file.getAbsolutePath());
            startAudioRecording(file);
            return;
        }
        Toast.makeText(getApplicationContext(), "fail to make file", 1).show();
    }
}
