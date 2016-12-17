package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.support.v4.p008d.p009a.C0090b;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;

/* renamed from: android.support.v4.h.ar */
public final class ar {
    static final av f434a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 14) {
            f434a = new au();
        } else if (i >= 11) {
            f434a = new at();
        } else {
            f434a = new as();
        }
    }

    public static MenuItem m860a(MenuItem menuItem, C0161n c0161n) {
        if (menuItem instanceof C0090b) {
            return ((C0090b) menuItem).m570a(c0161n);
        }
        Log.w("MenuItemCompat", "setActionProvider: item does not implement SupportMenuItem; ignoring");
        return menuItem;
    }

    public static MenuItem m861a(MenuItem menuItem, View view) {
        return menuItem instanceof C0090b ? ((C0090b) menuItem).setActionView(view) : f434a.m867a(menuItem, view);
    }

    public static View m862a(MenuItem menuItem) {
        return menuItem instanceof C0090b ? ((C0090b) menuItem).getActionView() : f434a.m868a(menuItem);
    }

    public static void m863a(MenuItem menuItem, int i) {
        if (menuItem instanceof C0090b) {
            ((C0090b) menuItem).setShowAsAction(i);
        } else {
            f434a.m869a(menuItem, i);
        }
    }

    public static MenuItem m864b(MenuItem menuItem, int i) {
        return menuItem instanceof C0090b ? ((C0090b) menuItem).setActionView(i) : f434a.m870b(menuItem, i);
    }

    public static boolean m865b(MenuItem menuItem) {
        return menuItem instanceof C0090b ? ((C0090b) menuItem).expandActionView() : f434a.m871b(menuItem);
    }

    public static boolean m866c(MenuItem menuItem) {
        return menuItem instanceof C0090b ? ((C0090b) menuItem).isActionViewExpanded() : f434a.m872c(menuItem);
    }
}
