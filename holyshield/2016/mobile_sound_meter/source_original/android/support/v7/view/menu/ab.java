package android.support.v7.view.menu;

import android.content.Context;
import android.os.Build.VERSION;
import android.support.v4.p008d.p009a.C0089a;
import android.support.v4.p008d.p009a.C0090b;
import android.support.v4.p008d.p009a.C0091c;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SubMenu;

public final class ab {
    public static Menu m2084a(Context context, C0089a c0089a) {
        if (VERSION.SDK_INT >= 14) {
            return new ac(context, c0089a);
        }
        throw new UnsupportedOperationException();
    }

    public static MenuItem m2085a(Context context, C0090b c0090b) {
        if (VERSION.SDK_INT >= 16) {
            return new C0279t(context, c0090b);
        }
        if (VERSION.SDK_INT >= 14) {
            return new C0274o(context, c0090b);
        }
        throw new UnsupportedOperationException();
    }

    public static SubMenu m2086a(Context context, C0091c c0091c) {
        if (VERSION.SDK_INT >= 14) {
            return new ae(context, c0091c);
        }
        throw new UnsupportedOperationException();
    }
}
