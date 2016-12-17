package android.support.v4.p003a;

import android.graphics.Rect;
import android.transition.Transition;
import android.transition.Transition.EpicenterCallback;

/* renamed from: android.support.v4.a.as */
final class as extends EpicenterCallback {
    final /* synthetic */ Rect f153a;

    as(Rect rect) {
        this.f153a = rect;
    }

    public Rect onGetEpicenter(Transition transition) {
        return this.f153a;
    }
}
