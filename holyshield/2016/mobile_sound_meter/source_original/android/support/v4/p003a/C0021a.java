package android.support.v4.p003a;

import android.app.Activity;
import android.os.Build.VERSION;
import android.support.v4.p002b.C0020a;

/* renamed from: android.support.v4.a.a */
public class C0021a extends C0020a {
    public static void m76a(Activity activity) {
        if (VERSION.SDK_INT >= 16) {
            C0026d.m291a(activity);
        } else {
            activity.finish();
        }
    }

    public static void m77b(Activity activity) {
        if (VERSION.SDK_INT >= 21) {
            C0022b.m236a(activity);
        } else {
            activity.finish();
        }
    }
}
