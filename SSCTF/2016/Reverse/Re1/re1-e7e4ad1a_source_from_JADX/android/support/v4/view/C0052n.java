package android.support.v4.view;

import android.view.MotionEvent;

/* renamed from: android.support.v4.view.n */
class C0052n implements C0051p {
    C0052n() {
    }

    public int m336a(MotionEvent motionEvent) {
        return 1;
    }

    public int m337a(MotionEvent motionEvent, int i) {
        return i == 0 ? 0 : -1;
    }

    public int m338b(MotionEvent motionEvent, int i) {
        if (i == 0) {
            return 0;
        }
        throw new IndexOutOfBoundsException("Pre-Eclair does not support multiple pointers");
    }

    public float m339c(MotionEvent motionEvent, int i) {
        if (i == 0) {
            return motionEvent.getX();
        }
        throw new IndexOutOfBoundsException("Pre-Eclair does not support multiple pointers");
    }

    public float m340d(MotionEvent motionEvent, int i) {
        if (i == 0) {
            return motionEvent.getY();
        }
        throw new IndexOutOfBoundsException("Pre-Eclair does not support multiple pointers");
    }
}
