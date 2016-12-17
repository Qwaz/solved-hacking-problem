package android.support.v4.p004h;

import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.view.View;

/* renamed from: android.support.v4.h.dw */
class dw {
    public static void m1285a(View view, ea eaVar) {
        AnimatorUpdateListener animatorUpdateListener = null;
        if (eaVar != null) {
            animatorUpdateListener = new dx(eaVar, view);
        }
        view.animate().setUpdateListener(animatorUpdateListener);
    }
}
