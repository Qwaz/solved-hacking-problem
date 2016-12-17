package android.support.v4.p002b;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Bundle;

/* renamed from: android.support.v4.b.a */
public class C0020a {
    public static final Drawable m74a(Context context, int i) {
        return VERSION.SDK_INT >= 21 ? C0051b.m432a(context, i) : context.getResources().getDrawable(i);
    }

    public static boolean m75a(Context context, Intent[] intentArr, Bundle bundle) {
        int i = VERSION.SDK_INT;
        if (i >= 16) {
            C0053d.m434a(context, intentArr, bundle);
            return true;
        } else if (i < 11) {
            return false;
        } else {
            C0052c.m433a(context, intentArr);
            return true;
        }
    }
}
