package android.support.v4.p003a;

import android.app.AppOpsManager;
import android.content.Context;

/* renamed from: android.support.v4.a.i */
class C0031i {
    public static int m298a(Context context, String str, String str2) {
        return ((AppOpsManager) context.getSystemService(AppOpsManager.class)).noteProxyOp(str, str2);
    }

    public static String m299a(String str) {
        return AppOpsManager.permissionToOp(str);
    }
}
