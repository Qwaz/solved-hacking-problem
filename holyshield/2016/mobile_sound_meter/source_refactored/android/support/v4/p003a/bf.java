package android.support.v4.p003a;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;

/* renamed from: android.support.v4.a.bf */
class bf extends be {
    bf() {
    }

    public Intent m270a(Activity activity) {
        Intent a = bg.m275a(activity);
        return a == null ? m273b(activity) : a;
    }

    public String m271a(Context context, ActivityInfo activityInfo) {
        String a = bg.m276a(activityInfo);
        return a == null ? super.m267a(context, activityInfo) : a;
    }

    public boolean m272a(Activity activity, Intent intent) {
        return bg.m277a(activity, intent);
    }

    Intent m273b(Activity activity) {
        return super.m266a(activity);
    }

    public void m274b(Activity activity, Intent intent) {
        bg.m278b(activity, intent);
    }
}
