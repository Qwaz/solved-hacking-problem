package android.support.v7.view.menu;

import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.content.DialogInterface.OnKeyListener;
import android.os.IBinder;
import android.support.v7.p014a.C0229s;
import android.support.v7.p014a.C0230t;
import android.support.v7.p015b.C0240i;
import android.view.KeyEvent;
import android.view.KeyEvent.DispatcherState;
import android.view.View;
import android.view.Window;
import android.view.WindowManager.LayoutParams;

/* renamed from: android.support.v7.view.menu.l */
class C0271l implements OnClickListener, OnDismissListener, OnKeyListener, C0207y {
    C0269g f1016a;
    private C0264i f1017b;
    private C0229s f1018c;
    private C0207y f1019d;

    public C0271l(C0264i c0264i) {
        this.f1017b = c0264i;
    }

    public void m2207a() {
        if (this.f1018c != null) {
            this.f1018c.dismiss();
        }
    }

    public void m2208a(IBinder iBinder) {
        C0264i c0264i = this.f1017b;
        C0230t c0230t = new C0230t(c0264i.m2131e());
        this.f1016a = new C0269g(c0230t.m1964a(), C0240i.abc_list_menu_item_layout);
        this.f1016a.m2199a((C0207y) this);
        this.f1017b.m2111a(this.f1016a);
        c0230t.m1968a(this.f1016a.m2196a(), this);
        View o = c0264i.m2141o();
        if (o != null) {
            c0230t.m1967a(o);
        } else {
            c0230t.m1966a(c0264i.m2140n()).m1969a(c0264i.m2139m());
        }
        c0230t.m1965a((OnKeyListener) this);
        this.f1018c = c0230t.m1970b();
        this.f1018c.setOnDismissListener(this);
        LayoutParams attributes = this.f1018c.getWindow().getAttributes();
        attributes.type = 1003;
        if (iBinder != null) {
            attributes.token = iBinder;
        }
        attributes.flags |= 131072;
        this.f1018c.show();
    }

    public void m2209a(C0264i c0264i, boolean z) {
        if (z || c0264i == this.f1017b) {
            m2207a();
        }
        if (this.f1019d != null) {
            this.f1019d.m1754a(c0264i, z);
        }
    }

    public boolean m2210a(C0264i c0264i) {
        return this.f1019d != null ? this.f1019d.m1755a(c0264i) : false;
    }

    public void onClick(DialogInterface dialogInterface, int i) {
        this.f1017b.m2117a((C0272m) this.f1016a.m2196a().getItem(i), 0);
    }

    public void onDismiss(DialogInterface dialogInterface) {
        this.f1016a.m2198a(this.f1017b, true);
    }

    public boolean onKey(DialogInterface dialogInterface, int i, KeyEvent keyEvent) {
        if (i == 82 || i == 4) {
            Window window;
            View decorView;
            DispatcherState keyDispatcherState;
            if (keyEvent.getAction() == 0 && keyEvent.getRepeatCount() == 0) {
                window = this.f1018c.getWindow();
                if (window != null) {
                    decorView = window.getDecorView();
                    if (decorView != null) {
                        keyDispatcherState = decorView.getKeyDispatcherState();
                        if (keyDispatcherState != null) {
                            keyDispatcherState.startTracking(keyEvent, this);
                            return true;
                        }
                    }
                }
            } else if (keyEvent.getAction() == 1 && !keyEvent.isCanceled()) {
                window = this.f1018c.getWindow();
                if (window != null) {
                    decorView = window.getDecorView();
                    if (decorView != null) {
                        keyDispatcherState = decorView.getKeyDispatcherState();
                        if (keyDispatcherState != null && keyDispatcherState.isTracking(keyEvent)) {
                            this.f1017b.m2115a(true);
                            dialogInterface.dismiss();
                            return true;
                        }
                    }
                }
            }
        }
        return this.f1017b.performShortcut(i, keyEvent, 0);
    }
}
