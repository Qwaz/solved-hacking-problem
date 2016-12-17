package me.daei.soundmeter;

import android.app.Activity;
import android.content.Context;
import android.util.DisplayMetrics;
import android.view.WindowManager;

/* renamed from: me.daei.soundmeter.f */
public class C0313f {
    public static float m2879a(Context context) {
        if (context instanceof Activity) {
            context = context.getApplicationContext();
        }
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        DisplayMetrics displayMetrics = new DisplayMetrics();
        windowManager.getDefaultDisplay().getMetrics(displayMetrics);
        return displayMetrics.density;
    }
}
