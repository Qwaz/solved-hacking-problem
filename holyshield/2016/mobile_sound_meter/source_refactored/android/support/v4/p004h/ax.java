package android.support.v4.p004h;

import android.view.MenuItem;
import android.view.View;

/* renamed from: android.support.v4.h.ax */
class ax {
    public static MenuItem m889a(MenuItem menuItem, View view) {
        return menuItem.setActionView(view);
    }

    public static View m890a(MenuItem menuItem) {
        return menuItem.getActionView();
    }

    public static void m891a(MenuItem menuItem, int i) {
        menuItem.setShowAsAction(i);
    }

    public static MenuItem m892b(MenuItem menuItem, int i) {
        return menuItem.setActionView(i);
    }
}
