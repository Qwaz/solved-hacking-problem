package android.support.v4.p003a;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;

/* renamed from: android.support.v4.a.bg */
class bg {
    public static Intent m275a(Activity activity) {
        return activity.getParentActivityIntent();
    }

    public static String m276a(ActivityInfo activityInfo) {
        return activityInfo.parentActivityName;
    }

    public static boolean m277a(Activity activity, Intent intent) {
        return activity.shouldUpRecreateTask(intent);
    }

    public static void m278b(Activity activity, Intent intent) {
        activity.navigateUpTo(intent);
    }
}
