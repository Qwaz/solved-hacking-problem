package android.support.v4.p004h;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater.Factory;
import android.view.View;

/* renamed from: android.support.v4.h.ah */
class ah implements Factory {
    final al f430a;

    ah(al alVar) {
        this.f430a = alVar;
    }

    public View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return this.f430a.m138a(null, str, context, attributeSet);
    }

    public String toString() {
        return getClass().getName() + "{" + this.f430a + "}";
    }
}
