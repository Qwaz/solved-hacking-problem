package android.support.v4.widget;

import android.util.Log;
import android.view.View;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/* renamed from: android.support.v4.widget.w */
class C0084w extends C0083v {
    private Method f331a;
    private Field f332b;

    C0084w() {
        try {
            this.f331a = View.class.getDeclaredMethod("getDisplayList", (Class[]) null);
        } catch (Throwable e) {
            Log.e("SlidingPaneLayout", "Couldn't fetch getDisplayList method; dimming won't work right.", e);
        }
        try {
            this.f332b = View.class.getDeclaredField("mRecreateDisplayList");
            this.f332b.setAccessible(true);
        } catch (Throwable e2) {
            Log.e("SlidingPaneLayout", "Couldn't fetch mRecreateDisplayList field; dimming will be slow.", e2);
        }
    }

    public void m536a(SlidingPaneLayout slidingPaneLayout, View view) {
        if (this.f331a == null || this.f332b == null) {
            view.invalidate();
            return;
        }
        try {
            this.f332b.setBoolean(view, true);
            this.f331a.invoke(view, (Object[]) null);
        } catch (Throwable e) {
            Log.e("SlidingPaneLayout", "Error refreshing display list state", e);
        }
        super.m535a(slidingPaneLayout, view);
    }
}
