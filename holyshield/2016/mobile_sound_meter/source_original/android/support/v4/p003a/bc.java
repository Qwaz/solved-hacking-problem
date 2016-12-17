package android.support.v4.p003a;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build.VERSION;
import android.support.v4.p002b.C0054e;

/* renamed from: android.support.v4.a.bc */
public final class bc {
    private static final bd f197a;

    static {
        if (VERSION.SDK_INT >= 16) {
            f197a = new bf();
        } else {
            f197a = new be();
        }
    }

    public static Intent m256a(Activity activity) {
        return f197a.m262a(activity);
    }

    public static Intent m257a(Context context, ComponentName componentName) {
        String b = bc.m260b(context, componentName);
        if (b == null) {
            return null;
        }
        ComponentName componentName2 = new ComponentName(componentName.getPackageName(), b);
        return bc.m260b(context, componentName2) == null ? C0054e.m435a(componentName2) : new Intent().setComponent(componentName2);
    }

    public static boolean m258a(Activity activity, Intent intent) {
        return f197a.m264a(activity, intent);
    }

    public static String m259b(Activity activity) {
        try {
            return bc.m260b((Context) activity, activity.getComponentName());
        } catch (Throwable e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String m260b(Context context, ComponentName componentName) {
        return f197a.m263a(context, context.getPackageManager().getActivityInfo(componentName, 128));
    }

    public static void m261b(Activity activity, Intent intent) {
        f197a.m265b(activity, intent);
    }
}
