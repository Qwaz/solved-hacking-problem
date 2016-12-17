package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.MotionEvent;

/* renamed from: android.support.v4.h.az */
public final class az {
    static final be f435a;

    static {
        if (VERSION.SDK_INT >= 12) {
            f435a = new bd();
        } else if (VERSION.SDK_INT >= 9) {
            f435a = new bc();
        } else if (VERSION.SDK_INT >= 5) {
            f435a = new bb();
        } else {
            f435a = new ba();
        }
    }

    public static int m895a(MotionEvent motionEvent) {
        return motionEvent.getAction() & 255;
    }

    public static int m896a(MotionEvent motionEvent, int i) {
        return f435a.m935a(motionEvent, i);
    }

    public static int m897b(MotionEvent motionEvent) {
        return (motionEvent.getAction() & 65280) >> 8;
    }

    public static int m898b(MotionEvent motionEvent, int i) {
        return f435a.m936b(motionEvent, i);
    }

    public static float m899c(MotionEvent motionEvent, int i) {
        return f435a.m937c(motionEvent, i);
    }

    public static int m900c(MotionEvent motionEvent) {
        return f435a.m934a(motionEvent);
    }

    public static float m901d(MotionEvent motionEvent, int i) {
        return f435a.m938d(motionEvent, i);
    }

    public static float m902e(MotionEvent motionEvent, int i) {
        return f435a.m939e(motionEvent, i);
    }
}
