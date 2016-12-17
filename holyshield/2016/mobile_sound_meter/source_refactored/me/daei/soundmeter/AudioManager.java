package me.daei.soundmeter;

import android.media.MediaRecorder;
import java.io.File;
import java.io.IOException;

/* renamed from: me.daei.soundmeter.e */
public class AudioManager {
    public File file;
    public boolean set;
    private MediaRecorder recorder;

    public AudioManager() {
        this.set = false;
    }

    public float getMaxAmplitude() {
        if (this.recorder == null) {
            return 5.0f;
        }
        try {
            return (float) this.recorder.getMaxAmplitude();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return 0.0f;
        }
    }

    public void setFile(File file) {
        this.file = file;
    }

    public boolean initRecorder() {
        if (this.file == null) {
            return false;
        }
        try {
            this.recorder = new MediaRecorder();
            this.recorder.setAudioSource(1);
            this.recorder.setOutputFormat(1);
            this.recorder.setAudioEncoder(1);
            this.recorder.setOutputFile(this.file.getAbsolutePath());
            this.recorder.prepare();
            this.recorder.start();
            this.set = true;
            return true;
        } catch (IOException e) {
            this.recorder.reset();
            this.recorder.release();
            this.recorder = null;
            this.set = false;
            e.printStackTrace();
            return false;
        } catch (IllegalStateException e2) {
            stopRecorder();
            e2.printStackTrace();
            this.set = false;
            return false;
        }
    }

    public void stopRecorder() {
        if (this.recorder != null) {
            if (this.set) {
                try {
                    this.recorder.stop();
                    this.recorder.release();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            this.recorder = null;
            this.set = false;
        }
    }

    public void cancelRecording() {
        stopRecorder();
        if (this.file != null) {
            this.file.delete();
            this.file = null;
        }
    }
}
