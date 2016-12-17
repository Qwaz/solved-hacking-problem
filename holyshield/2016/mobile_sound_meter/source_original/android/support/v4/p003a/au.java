package android.support.v4.p003a;

import android.graphics.Rect;
import android.transition.Transition;
import android.transition.Transition.EpicenterCallback;

/* renamed from: android.support.v4.a.au */
final class au extends EpicenterCallback {
    final /* synthetic */ aw f161a;
    private Rect f162b;

    au(aw awVar) {
        this.f161a = awVar;
    }

    public Rect onGetEpicenter(Transition transition) {
        if (this.f162b == null && this.f161a.f174a != null) {
            this.f162b = ar.m230c(this.f161a.f174a);
        }
        return this.f162b;
    }
}
