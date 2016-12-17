package android.support.v4.widget;

import android.os.Build.VERSION;
import android.widget.ListView;

public final class aa {
    public static void m1423a(ListView listView, int i) {
        if (VERSION.SDK_INT >= 19) {
            ac.m1425a(listView, i);
        } else {
            ab.m1424a(listView, i);
        }
    }
}
