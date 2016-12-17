package android.support.v4.p004h;

import android.view.MotionEvent;

/* renamed from: android.support.v4.h.ba */
class ba implements be {
    ba() {
    }

    public int m940a(MotionEvent motionEvent) {
        return 0;
    }

    public int m941a(MotionEvent motionEvent, int i) {
        return i == 0 ? 0 : -1;
    }

    public int m942b(MotionEvent motionEvent, int i) {
        if (i == 0) {
            return 0;
        }
        throw new IndexOutOfBoundsException("Pre-Eclair does not support multiple pointers");
    }

    public float m943c(MotionEvent motionEvent, int i) {
        if (i == 0) {
            return motionEvent.getX();
        }
        throw new IndexOutOfBoundsException("Pre-Eclair does not support multiple pointers");
    }

    public float m944d(MotionEvent motionEvent, int i) {
        if (i == 0) {
            return motionEvent.getY();
        }
        throw new IndexOutOfBoundsException("Pre-Eclair does not support multiple pointers");
    }

    public float m945e(MotionEvent motionEvent, int i) {
        return 0.0f;
    }
}
