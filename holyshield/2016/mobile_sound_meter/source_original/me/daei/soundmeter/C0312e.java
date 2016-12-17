package me.daei.soundmeter;

import android.media.MediaRecorder;
import java.io.File;
import java.io.IOException;

/* renamed from: me.daei.soundmeter.e */
public class C0312e {
    public File f1627a;
    public boolean f1628b;
    private MediaRecorder f1629c;

    public C0312e() {
        this.f1628b = false;
    }

    public float m2874a() {
        if (this.f1629c == null) {
            return 5.0f;
        }
        try {
            return (float) this.f1629c.getMaxAmplitude();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return 0.0f;
        }
    }

    public void m2875a(File file) {
        this.f1627a = file;
    }

    public boolean m2876b() {
        if (this.f1627a == null) {
            return false;
        }
        try {
            this.f1629c = new MediaRecorder();
            this.f1629c.setAudioSource(1);
            this.f1629c.setOutputFormat(1);
            this.f1629c.setAudioEncoder(1);
            this.f1629c.setOutputFile(this.f1627a.getAbsolutePath());
            this.f1629c.prepare();
            this.f1629c.start();
            this.f1628b = true;
            return true;
        } catch (IOException e) {
            this.f1629c.reset();
            this.f1629c.release();
            this.f1629c = null;
            this.f1628b = false;
            e.printStackTrace();
            return false;
        } catch (IllegalStateException e2) {
            m2877c();
            e2.printStackTrace();
            this.f1628b = false;
            return false;
        }
    }

    public void m2877c() {
        if (this.f1629c != null) {
            if (this.f1628b) {
                try {
                    this.f1629c.stop();
                    this.f1629c.release();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            this.f1629c = null;
            this.f1628b = false;
        }
    }

    public void m2878d() {
        m2877c();
        if (this.f1627a != null) {
            this.f1627a.delete();
            this.f1627a = null;
        }
    }
}
