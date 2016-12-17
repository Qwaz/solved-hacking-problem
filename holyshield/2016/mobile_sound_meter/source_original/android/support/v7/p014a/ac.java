package android.support.v7.p014a;

import android.app.UiModeManager;
import android.content.Context;
import android.view.Window;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.ac */
class ac extends aa {
    private final UiModeManager f613r;

    ac(Context context, Window window, C0209v c0209v) {
        super(context, window, c0209v);
        this.f613r = (UiModeManager) context.getSystemService("uimode");
    }

    Callback m1741a(Callback callback) {
        return new ad(this, callback);
    }

    int m1742d(int i) {
        return (i == 0 && this.f613r.getNightMode() == 0) ? -1 : super.m1737d(i);
    }
}
