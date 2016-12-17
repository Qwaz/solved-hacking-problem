package android.support.v7.widget;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build.VERSION;
import android.support.v4.widget.ah;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import android.view.ViewTreeObserver.OnScrollChangedListener;
import android.widget.PopupWindow;
import java.lang.reflect.Field;

public class az extends PopupWindow {
    private static final boolean f1333a;
    private boolean f1334b;

    static {
        f1333a = VERSION.SDK_INT < 21;
    }

    public az(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        dh a = dh.m2710a(context, attributeSet, C0243l.PopupWindow, i, 0);
        if (a.m2725f(C0243l.PopupWindow_overlapAnchor)) {
            m2532a(a.m2715a(C0243l.PopupWindow_overlapAnchor, false));
        }
        setBackgroundDrawable(a.m2713a(C0243l.PopupWindow_android_popupBackground));
        a.m2714a();
        if (VERSION.SDK_INT < 14) {
            m2531a((PopupWindow) this);
        }
    }

    private static void m2531a(PopupWindow popupWindow) {
        try {
            Field declaredField = PopupWindow.class.getDeclaredField("mAnchor");
            declaredField.setAccessible(true);
            Field declaredField2 = PopupWindow.class.getDeclaredField("mOnScrollChangedListener");
            declaredField2.setAccessible(true);
            declaredField2.set(popupWindow, new ba(declaredField, popupWindow, (OnScrollChangedListener) declaredField2.get(popupWindow)));
        } catch (Throwable e) {
            Log.d("AppCompatPopupWindow", "Exception while installing workaround OnScrollChangedListener", e);
        }
    }

    public void m2532a(boolean z) {
        if (f1333a) {
            this.f1334b = z;
        } else {
            ah.m1434a((PopupWindow) this, z);
        }
    }

    public void showAsDropDown(View view, int i, int i2) {
        if (f1333a && this.f1334b) {
            i2 -= view.getHeight();
        }
        super.showAsDropDown(view, i, i2);
    }

    @TargetApi(19)
    public void showAsDropDown(View view, int i, int i2, int i3) {
        if (f1333a && this.f1334b) {
            i2 -= view.getHeight();
        }
        super.showAsDropDown(view, i, i2, i3);
    }

    public void update(View view, int i, int i2, int i3, int i4) {
        int height = (f1333a && this.f1334b) ? i2 - view.getHeight() : i2;
        super.update(view, i, height, i3, i4);
    }
}
