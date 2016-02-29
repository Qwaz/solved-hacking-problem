package android.support.v4.view;

import android.view.MotionEvent;

/* renamed from: android.support.v4.view.q */
class C0054q {
    public static int m346a(MotionEvent motionEvent) {
        return motionEvent.getPointerCount();
    }

    public static int m347a(MotionEvent motionEvent, int i) {
        return motionEvent.findPointerIndex(i);
    }

    public static int m348b(MotionEvent motionEvent, int i) {
        return motionEvent.getPointerId(i);
    }

    public static float m349c(MotionEvent motionEvent, int i) {
        return motionEvent.getX(i);
    }

    public static float m350d(MotionEvent motionEvent, int i) {
        return motionEvent.getY(i);
    }
}
