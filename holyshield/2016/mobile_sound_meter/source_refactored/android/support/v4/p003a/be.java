package android.support.v4.p003a;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.support.v4.p002b.C0054e;
import android.util.Log;

/* renamed from: android.support.v4.a.be */
class be implements bd {
    be() {
    }

    public Intent m266a(Activity activity) {
        String b = bc.m259b(activity);
        if (b == null) {
            return null;
        }
        ComponentName componentName = new ComponentName(activity, b);
        try {
            return bc.m260b((Context) activity, componentName) == null ? C0054e.m435a(componentName) : new Intent().setComponent(componentName);
        } catch (NameNotFoundException e) {
            Log.e("NavUtils", "getParentActivityIntent: bad parentActivityName '" + b + "' in manifest");
            return null;
        }
    }

    public String m267a(Context context, ActivityInfo activityInfo) {
        if (activityInfo.metaData == null) {
            return null;
        }
        String string = activityInfo.metaData.getString("android.support.PARENT_ACTIVITY");
        return string == null ? null : string.charAt(0) == '.' ? context.getPackageName() + string : string;
    }

    public boolean m268a(Activity activity, Intent intent) {
        String action = activity.getIntent().getAction();
        return (action == null || action.equals("android.intent.action.MAIN")) ? false : true;
    }

    public void m269b(Activity activity, Intent intent) {
        intent.addFlags(67108864);
        activity.startActivity(intent);
        activity.finish();
    }
}
