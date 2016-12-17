package android.support.v4.p002b;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Build.VERSION;

/* renamed from: android.support.v4.b.e */
public final class C0054e {
    private static final C0055f f334a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 15) {
            f334a = new C0058i();
        } else if (i >= 11) {
            f334a = new C0057h();
        } else {
            f334a = new C0056g();
        }
    }

    public static Intent m435a(ComponentName componentName) {
        return f334a.m436a(componentName);
    }
}
