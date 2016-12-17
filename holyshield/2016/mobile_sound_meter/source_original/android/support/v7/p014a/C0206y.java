package android.support.v7.p014a;

import android.support.v7.view.C0205n;
import android.support.v7.view.menu.C0264i;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.View;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.y */
class C0206y extends C0205n {
    final /* synthetic */ C0202x f611a;

    C0206y(C0202x c0202x, Callback callback) {
        this.f611a = c0202x;
        super(callback);
    }

    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        return this.f611a.m1646a(keyEvent) || super.dispatchKeyEvent(keyEvent);
    }

    public boolean dispatchKeyShortcutEvent(KeyEvent keyEvent) {
        return super.dispatchKeyShortcutEvent(keyEvent) || this.f611a.m1645a(keyEvent.getKeyCode(), keyEvent);
    }

    public void onContentChanged() {
    }

    public boolean onCreatePanelMenu(int i, Menu menu) {
        return (i != 0 || (menu instanceof C0264i)) ? super.onCreatePanelMenu(i, menu) : false;
    }

    public boolean onMenuOpened(int i, Menu menu) {
        super.onMenuOpened(i, menu);
        this.f611a.m1649b(i, menu);
        return true;
    }

    public void onPanelClosed(int i, Menu menu) {
        super.onPanelClosed(i, menu);
        this.f611a.m1643a(i, menu);
    }

    public boolean onPreparePanel(int i, View view, Menu menu) {
        C0264i c0264i = menu instanceof C0264i ? (C0264i) menu : null;
        if (i == 0 && c0264i == null) {
            return false;
        }
        if (c0264i != null) {
            c0264i.m2126c(true);
        }
        boolean onPreparePanel = super.onPreparePanel(i, view, menu);
        if (c0264i == null) {
            return onPreparePanel;
        }
        c0264i.m2126c(false);
        return onPreparePanel;
    }
}
