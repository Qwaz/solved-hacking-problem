package android.support.v4.view;

import android.os.Build.VERSION;
import android.view.MotionEvent;

/* renamed from: android.support.v4.view.m */
public class C0050m {
    static final C0051p f263a;

    static {
        if (VERSION.SDK_INT >= 5) {
            f263a = new C0053o();
        } else {
            f263a = new C0052n();
        }
    }

    public static int m324a(MotionEvent motionEvent) {
        return motionEvent.getAction() & 255;
    }

    public static int m325a(MotionEvent motionEvent, int i) {
        return f263a.m332a(motionEvent, i);
    }

    public static int m326b(MotionEvent motionEvent) {
        return (motionEvent.getAction() & 65280) >> 8;
    }

    public static int m327b(MotionEvent motionEvent, int i) {
        return f263a.m333b(motionEvent, i);
    }

    public static float m328c(MotionEvent motionEvent, int i) {
        return f263a.m334c(motionEvent, i);
    }

    public static int m329c(MotionEvent motionEvent) {
        return f263a.m331a(motionEvent);
    }

    public static float m330d(MotionEvent motionEvent, int i) {
        return f263a.m335d(motionEvent, i);
    }
}
