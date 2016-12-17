package android.support.v4.p002b;

import android.content.Context;
import android.os.Process;
import android.support.v4.p003a.C0027e;

/* renamed from: android.support.v4.b.n */
public final class C0061n {
    public static int m452a(Context context, String str) {
        return C0061n.m453a(context, str, Process.myPid(), Process.myUid(), context.getPackageName());
    }

    public static int m453a(Context context, String str, int i, int i2, String str2) {
        if (context.checkPermission(str, i, i2) == -1) {
            return -1;
        }
        String a = C0027e.m293a(str);
        if (a == null) {
            return 0;
        }
        if (str2 == null) {
            String[] packagesForUid = context.getPackageManager().getPackagesForUid(i2);
            if (packagesForUid == null || packagesForUid.length <= 0) {
                return -1;
            }
            str2 = packagesForUid[0];
        }
        return C0027e.m292a(context, a, str2) != 0 ? -2 : 0;
    }
}
