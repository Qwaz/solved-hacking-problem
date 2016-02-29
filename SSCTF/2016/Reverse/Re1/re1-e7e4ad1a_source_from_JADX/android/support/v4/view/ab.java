package android.support.v4.view;

import android.graphics.Paint;
import android.view.View;

class ab extends aa {
    ab() {
    }

    long m269a() {
        return ai.m282a();
    }

    public void m270a(View view, int i, Paint paint) {
        ai.m283a(view, i, paint);
    }

    public void m271a(View view, Paint paint) {
        m270a(view, m272c(view), paint);
        view.invalidate();
    }

    public int m272c(View view) {
        return ai.m281a(view);
    }
}
