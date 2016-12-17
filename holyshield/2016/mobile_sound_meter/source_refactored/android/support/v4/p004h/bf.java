package android.support.v4.p004h;

import android.view.MotionEvent;

/* renamed from: android.support.v4.h.bf */
class bf {
    public static int m952a(MotionEvent motionEvent, int i) {
        return motionEvent.findPointerIndex(i);
    }

    public static int m953b(MotionEvent motionEvent, int i) {
        return motionEvent.getPointerId(i);
    }

    public static float m954c(MotionEvent motionEvent, int i) {
        return motionEvent.getX(i);
    }

    public static float m955d(MotionEvent motionEvent, int i) {
        return motionEvent.getY(i);
    }
}
