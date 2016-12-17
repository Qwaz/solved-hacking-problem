package android.support.v7.p014a;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.Configuration;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.view.MenuInflater;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import android.view.Window;

/* renamed from: android.support.v7.a.w */
public abstract class C0201w {
    private static int f566a;

    static {
        f566a = -1;
    }

    C0201w() {
    }

    public static C0201w m1617a(Activity activity, C0209v c0209v) {
        return C0201w.m1619a(activity, activity.getWindow(), c0209v);
    }

    public static C0201w m1618a(Dialog dialog, C0209v c0209v) {
        return C0201w.m1619a(dialog.getContext(), dialog.getWindow(), c0209v);
    }

    private static C0201w m1619a(Context context, Window window, C0209v c0209v) {
        int i = VERSION.SDK_INT;
        return i >= 23 ? new ac(context, window, c0209v) : i >= 14 ? new aa(context, window, c0209v) : i >= 11 ? new C0204z(context, window, c0209v) : new ae(context, window, c0209v);
    }

    public static int m1620i() {
        return f566a;
    }

    public abstract C0200a m1621a();

    public abstract View m1622a(int i);

    public abstract void m1623a(Configuration configuration);

    public abstract void m1624a(Bundle bundle);

    public abstract void m1625a(View view);

    public abstract void m1626a(View view, LayoutParams layoutParams);

    public abstract void m1627a(CharSequence charSequence);

    public abstract MenuInflater m1628b();

    public abstract void m1629b(int i);

    public abstract void m1630b(Bundle bundle);

    public abstract void m1631b(View view, LayoutParams layoutParams);

    public abstract void m1632c();

    public abstract void m1633c(Bundle bundle);

    public abstract boolean m1634c(int i);

    public abstract void m1635d();

    public abstract void m1636e();

    public abstract void m1637f();

    public abstract void m1638g();

    public abstract boolean m1639h();
}
